const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for storefront
app.use(cors({ origin: true, credentials: true }));

// Express JSON body parser
app.use(express.json());

// Initialize Razorpay SDK
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_TM9D2mb6BUdPQ6',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret'
});

// Server-side authoritative product pricing catalog
const PRODUCT_CATALOG = {
    "Sthirah Cane Jaggery Powder": { price: 110, mrp: 136, taxPct: 5, hsn: "17011490" }
};

// Shipping Matrix per 1KG weight
const SHIPPING_MATRIX = {
    "Tamil Nadu": { zone: "Local", rate1kg: 41.50 },
    "Karnataka": { zone: "Regional", rate1kg: 51.00 },
    "Kerala": { zone: "Regional", rate1kg: 51.00 },
    "Andhra Pradesh": { zone: "Metro", rate1kg: 60.00 },
    "Telangana": { zone: "Metro", rate1kg: 60.00 },
    "Maharashtra": { zone: "National", rate1kg: 67.50 },
    "Gujarat": { zone: "National", rate1kg: 67.50 },
    "Delhi": { zone: "National", rate1kg: 81.00 },
    "West Bengal": { zone: "National", rate1kg: 81.00 },
    "Other States": { zone: "Remote", rate1kg: 76.50 }
};

/**
 * Helper to calculate authoritative shipping cost
 */
function getShippingCost(stateName, totalWeightKg) {
    const entry = SHIPPING_MATRIX[stateName] || SHIPPING_MATRIX["Other States"];
    return entry.rate1kg * totalWeightKg;
}

/**
 * 1. Create Razorpay Order Endpoint
 * Calculates authoritative order amount on server side and calls Razorpay API
 */
app.post('/api/create-razorpay-order', async (req, res) => {
    try {
        const { cart, stateName, userEmail } = req.body;

        if (!cart || !Array.isArray(cart) || cart.length === 0) {
            return res.status(400).json({ success: false, error: "Cart cannot be empty" });
        }

        let itemTotal = 0;
        let totalItemsKg = 0;

        cart.forEach(item => {
            const qty = parseInt(item.qty) || 1;
            const prod = PRODUCT_CATALOG[item.name] || { price: 110 };
            itemTotal += prod.price * qty;
            totalItemsKg += qty;
        });

        const shippingCost = getShippingCost(stateName || "Other States", totalItemsKg);
        const grandTotal = Math.ceil(itemTotal + shippingCost);
        const amountInPaise = grandTotal * 100;

        const receiptId = `receipt_sthirah_${Date.now()}`;
        const razorpayOrder = await razorpay.orders.create({
            amount: amountInPaise,
            currency: "INR",
            receipt: receiptId,
            notes: {
                userEmail: userEmail || "guest",
                shippingState: stateName || "Other States",
                totalItemsKg: totalItemsKg
            }
        });

        return res.json({
            success: true,
            order_id: razorpayOrder.id,
            key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_TM9D2mb6BUdPQ6',
            amount: amountInPaise,
            currency: "INR",
            grandTotal: grandTotal
        });

    } catch (err) {
        console.error("Error creating Razorpay order:", err);
        return res.status(500).json({ success: false, error: "Failed to create payment order on server" });
    }
});

/**
 * 2. Verify Razorpay Payment Signature Endpoint
 * Verifies cryptographic HMAC-SHA256 signature server-side
 */
app.post('/api/verify-payment', (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ success: false, error: "Missing required payment verification parameters" });
        }

        const secret = process.env.RAZORPAY_KEY_SECRET || 'placeholder_secret';
        const generatedSignature = crypto
            .createHmac('sha256', secret)
            .update(`${razorpay_order_id}|${razorpay_payment_id}`)
            .digest('hex');

        // Constant-time comparison to prevent timing side-channel attacks
        const sigBuffer = Buffer.from(razorpay_signature, 'utf8');
        const genBuffer = Buffer.from(generatedSignature, 'utf8');

        if (sigBuffer.length !== genBuffer.length || !crypto.timingSafeEqual(sigBuffer, genBuffer)) {
            console.warn(`[SECURITY ALERT] Invalid payment signature attempt for order ${razorpay_order_id}`);
            return res.status(400).json({ success: false, error: "Invalid payment cryptographic signature" });
        }

        console.log(`[SUCCESS] Payment verified for Order ID: ${razorpay_order_id}, Payment ID: ${razorpay_payment_id}`);
        return res.json({
            success: true,
            message: "Payment verified successfully via cryptographic HMAC-SHA256 signature",
            paymentId: razorpay_payment_id,
            orderId: razorpay_order_id
        });

    } catch (err) {
        console.error("Error in signature verification:", err);
        return res.status(500).json({ success: false, error: "Server signature verification failed" });
    }
});

/**
 * 3. Razorpay Webhook Endpoint
 * Asynchronously confirms payments directly from Razorpay servers
 */
app.post('/api/razorpay-webhook', (req, res) => {
    try {
        const webhookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || 'sthirah_webhook_secret_placeholder';
        const signature = req.headers['x-razorpay-signature'];

        const expectedSig = crypto
            .createHmac('sha256', webhookSecret)
            .update(JSON.stringify(req.body))
            .digest('hex');

        if (signature !== expectedSig) {
            console.warn("[SECURITY ALERT] Invalid Razorpay webhook signature");
            return res.status(400).send("Invalid webhook signature");
        }

        const event = req.body.event;
        if (event === 'order.paid' || event === 'payment.captured') {
            const paymentObj = req.body.payload.payment.entity;
            console.log(`[WEBHOOK SUCCESS] Asynchronous payment confirmation received: ${paymentObj.id}`);
            // Fulfill order in database...
        }

        return res.status(200).json({ status: "ok" });
    } catch (err) {
        console.error("Webhook processing error:", err);
        return res.status(500).send("Webhook error");
    }
});

/**
 * 4. Secure Admin Authentication Endpoint
 * Verifies admin credentials on server side without revealing passwords in JS bundle
 */
app.post('/api/admin-login', (req, res) => {
    try {
        const { user, pass } = req.body;
        const validUser = process.env.ADMIN_USER || "Pradheep";
        const validPass = process.env.ADMIN_PASS || "Sthirah@2026";

        const userMatch = user === validUser;
        const passMatch = pass === validPass;

        if (userMatch && passMatch) {
            // Generate temporary session token
            const sessionToken = crypto.randomBytes(32).toString('hex');
            return res.json({ success: true, token: sessionToken, user: validUser });
        } else {
            return res.status(401).json({ success: false, error: "Access Denied: Invalid admin credentials" });
        }
    } catch (err) {
        console.error("Admin login error:", err);
        return res.status(500).json({ success: false, error: "Internal authentication error" });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`[STHIRAH BACKEND API] Server running securely on port ${PORT}`);
});
