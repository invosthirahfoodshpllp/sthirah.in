const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Hardening: Disable X-Powered-By fingerprinting header
app.disable('x-powered-by');

// Security Hardening: HTTP Security Headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Enable CORS for storefront
app.use(cors({ origin: true, credentials: true }));

// Express JSON body parser with 10kb size limit to prevent DoS attacks
app.use(express.json({ limit: '10kb' }));

// In-Memory Rate Limiting for Admin Login Brute Force Protection
const loginAttempts = new Map();
function checkLoginRateLimit(ip) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const maxAttempts = 10;

    const record = loginAttempts.get(ip) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
        record.count = 1;
        record.resetTime = now + windowMs;
    } else {
        record.count++;
    }

    loginAttempts.set(ip, record);
    return record.count <= maxAttempts;
}

// Initialize Razorpay SDK
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_TVCOvSCHaLoXeY',
    key_secret: process.env.RAZORPAY_KEY_SECRET || '9fzomwKMYtsRYrci5Eg1jH6Y'
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
 * Endpoint aliases: POST /api/create-order and POST /api/create-razorpay-order
 */
app.post(['/api/create-order', '/api/create-razorpay-order'], async (req, res) => {
    try {
        const { amount, currency, receipt, cart, stateName, userEmail } = req.body;

        let amountInPaise = 0;
        let grandTotal = 0;

        if (amount && parseInt(amount) >= 100) {
            amountInPaise = parseInt(amount);
            grandTotal = Math.ceil(amountInPaise / 100);
        } else if (cart && Array.isArray(cart) && cart.length > 0) {
            let itemTotal = 0;
            let totalItemsKg = 0;

            cart.forEach(item => {
                const qty = parseInt(item.qty) || 1;
                const prod = PRODUCT_CATALOG[item.name] || { price: 110 };
                itemTotal += prod.price * qty;
                totalItemsKg += qty;
            });

            const shippingCost = getShippingCost(stateName || "Other States", totalItemsKg);
            grandTotal = Math.ceil(itemTotal + shippingCost);
            amountInPaise = grandTotal * 100;
        } else {
            return res.status(400).json({ success: false, error: "Minimum order amount must be at least 100 paise (₹1.00) or valid cart items required" });
        }

        if (amountInPaise < 100) {
            return res.status(400).json({ success: false, error: "Minimum order amount is 100 paise" });
        }

        const receiptId = receipt || `receipt_sthirah_${Date.now()}`;
        const razorpayOrder = await razorpay.orders.create({
            amount: amountInPaise,
            currency: currency || "INR",
            receipt: receiptId,
            notes: {
                userEmail: userEmail || "guest",
                shippingState: stateName || "Other States"
            }
        });

        return res.json({
            success: true,
            order_id: razorpayOrder.id,
            id: razorpayOrder.id,
            key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_TVCOvSCHaLoXeY',
            amount: amountInPaise,
            currency: currency || "INR",
            grandTotal: grandTotal
        });

    } catch (err) {
        console.error("Error creating Razorpay order:", err);
        return res.status(500).json({ success: false, error: "Failed to create payment order on server" });
    }
});

/**
 * 2. Verify Razorpay Payment Signature Endpoint
 * Endpoint: POST /api/verify-payment
 * HMAC-SHA256(order_id + "|" + payment_id, RAZORPAY_KEY_SECRET)
 */
app.post('/api/verify-payment', (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ success: false, error: "Missing required payment verification parameters: razorpay_order_id, razorpay_payment_id, and razorpay_signature are mandatory" });
        }

        const secret = process.env.RAZORPAY_KEY_SECRET || '9fzomwKMYtsRYrci5Eg1jH6Y';
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
        const clientIp = req.ip || req.connection.remoteAddress || "127.0.0.1";
        if (!checkLoginRateLimit(clientIp)) {
            console.warn(`[SECURITY ALERT] Too many admin login attempts from IP: ${clientIp}`);
            return res.status(429).json({ success: false, error: "Too many login attempts. Please try again after 15 minutes." });
        }

        const { user, pass } = req.body;
        const validUser = process.env.ADMIN_USER || "Pradheep";
        const validPass = process.env.ADMIN_PASS || "Sthirah@2026";

        const userBuf = Buffer.from(user || "", 'utf8');
        const validUserBuf = Buffer.from(validUser, 'utf8');
        const passBuf = Buffer.from(pass || "", 'utf8');
        const validPassBuf = Buffer.from(validPass, 'utf8');

        const userMatch = userBuf.length === validUserBuf.length && crypto.timingSafeEqual(userBuf, validUserBuf);
        const passMatch = passBuf.length === validPassBuf.length && crypto.timingSafeEqual(passBuf, validPassBuf);

        if (userMatch && passMatch) {
            // Generate temporary secure session token
            const sessionToken = crypto.randomBytes(32).toString('hex');
            console.log(`[SECURITY LOG] Successful admin login for user: ${validUser}`);
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
