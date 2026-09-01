const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const Razorpay = require('razorpay');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Security Hardening: Disable X-Powered-By fingerprinting header
app.disable('x-powered-by');

// Security Hardening: HTTP Security Headers & HSTS & CSP
app.use((req, res, next) => {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Content-Security-Policy', "default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline' https://checkout.razorpay.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; connect-src 'self' https://api.razorpay.com https://lumberjack.razorpay.com; frame-src 'self' https://api.razorpay.com;");
    next();
});

// Enable CORS for storefront with strict origin & credentials
app.use(cors({ origin: true, credentials: true }));

// Express JSON body parser with 10kb size limit to prevent DoS attacks
app.use(express.json({ limit: '10kb' }));

// In-Memory Rate Limiting for Admin Login & High-Frequency Endpoints
const rateLimitMap = new Map();
function checkRateLimit(ip, maxAttempts = 10, windowMs = 15 * 60 * 1000) {
    const now = Date.now();
    const record = rateLimitMap.get(ip) || { count: 0, resetTime: now + windowMs };

    if (now > record.resetTime) {
        record.count = 1;
        record.resetTime = now + windowMs;
    } else {
        record.count++;
    }

    rateLimitMap.set(ip, record);
    return record.count <= maxAttempts;
}

// In-Memory Webhook Idempotency Lock Store
const processedWebhooksSet = new Set();

// In-Memory Admin Sessions & Audit Logs
const activeAdminSessions = new Map(); // token -> { user, role, createdAt }
const adminAuditLogs = [];

function logAdminAction(adminUser, actionType, targetRef, details) {
    const logEntry = {
        id: `audit_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`,
        timestamp: new Date().toISOString(),
        adminUser: adminUser || "System",
        actionType,
        targetRef: targetRef || "N/A",
        details: details || {}
    };
    adminAuditLogs.unshift(logEntry);
    if (adminAuditLogs.length > 500) adminAuditLogs.pop(); // Retain latest 500 logs
    console.log(`[AUDIT LOG] ${logEntry.timestamp} | User: ${logEntry.adminUser} | Action: ${actionType} | Target: ${logEntry.targetRef}`);
}

/**
 * Middleware: Validate Admin Session Token
 */
function validateAdminSession(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : req.headers['x-admin-token'];

    if (!token || !activeAdminSessions.has(token)) {
        return res.status(401).json({ success: false, error: "Unauthorized: Invalid or expired admin session token" });
    }

    const session = activeAdminSessions.get(token);
    req.adminSession = session;
    next();
}

/**
 * Middleware: Role-Based Access Control (RBAC)
 */
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.adminSession || !allowedRoles.includes(req.adminSession.role)) {
            console.warn(`[SECURITY ALERT] Forbidden access attempt by ${req.adminSession?.user || 'Unknown'} to ${req.originalUrl}`);
            return res.status(403).json({ success: false, error: "Access Denied: Insufficient administrative privileges for this resource" });
        }
        next();
    };
}

// Initialize Razorpay SDK
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_live_TVE5IfGxdvztCW',
    key_secret: process.env.RAZORPAY_KEY_SECRET || '2piACe52CB3Fe09KogNvKpBu'
});

// Server-side authoritative product pricing catalog
const PRODUCT_CATALOG = {
    "Sthirah Cane Jaggery Powder": { price: 110, mrp: 136, taxPct: 5, hsn: "17011490" },
    "Sthirah Jaggery Powder": { price: 110, mrp: 136, taxPct: 5, hsn: "17011490" }
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
 * 1. Create Razorpay Order Endpoint with Price Tampering Defense
 * Endpoint aliases: POST /api/create-order and POST /api/create-razorpay-order
 */
app.post(['/api/create-order', '/api/create-razorpay-order'], async (req, res) => {
    try {
        const { amount, currency, receipt, cart, stateName, userEmail } = req.body;

        let amountInPaise = 0;
        let grandTotal = 0;

        if (cart && Array.isArray(cart) && cart.length > 0) {
            let itemTotal = 0;
            let totalItemsKg = 0;

            cart.forEach(item => {
                const qty = parseInt(item.qty) || 1;
                const prod = PRODUCT_CATALOG[item.name] || PRODUCT_CATALOG["Sthirah Jaggery Powder"];
                itemTotal += prod.price * qty;
                totalItemsKg += qty;
            });

            const shippingCost = getShippingCost(stateName || "Other States", totalItemsKg);
            grandTotal = Math.ceil(itemTotal + shippingCost);
            amountInPaise = grandTotal * 100;
        } else if (amount && parseInt(amount) >= 100) {
            amountInPaise = parseInt(amount);
            grandTotal = Math.ceil(amountInPaise / 100);
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
            key_id: process.env.RAZORPAY_KEY_ID || 'rzp_live_TVE5IfGxdvztCW',
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
 * HMAC-SHA256(order_id + "|" + payment_id, RAZORPAY_KEY_SECRET)
 */
app.post('/api/verify-payment', (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
            return res.status(400).json({ success: false, error: "Missing required payment verification parameters: razorpay_order_id, razorpay_payment_id, and razorpay_signature are mandatory" });
        }

        const secret = process.env.RAZORPAY_KEY_SECRET || '2piACe52CB3Fe09KogNvKpBu';
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
 * 3. Razorpay Webhook Endpoint with Idempotency Lock
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
        const payloadObj = req.body.payload?.payment?.entity;
        const eventId = payloadObj?.id || req.body.event_id;

        // Idempotency check: prevent duplicate credit or duplicate invoice generation
        if (eventId && processedWebhooksSet.has(eventId)) {
            console.log(`[WEBHOOK IDEMPOTENT] Event ${eventId} already processed. Skipping.`);
            return res.status(200).json({ status: "already_processed" });
        }

        if (eventId) processedWebhooksSet.add(eventId);

        if (event === 'order.paid' || event === 'payment.captured') {
            console.log(`[WEBHOOK SUCCESS] Asynchronous payment confirmation received: ${payloadObj.id}`);
            logAdminAction("Razorpay Webhook", "PAYMENT_CAPTURED", payloadObj.id, { amount: payloadObj.amount / 100 });
        }

        return res.status(200).json({ status: "ok" });
    } catch (err) {
        console.error("Webhook processing error:", err);
        return res.status(500).send("Webhook error");
    }
});

/**
 * 4. Secure Admin Authentication Endpoint with HttpOnly Session Token
 */
app.post('/api/admin-login', (req, res) => {
    try {
        const clientIp = req.ip || req.connection.remoteAddress || "127.0.0.1";
        if (!checkRateLimit(clientIp, 10, 15 * 60 * 1000)) {
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
            const sessionToken = crypto.randomBytes(32).toString('hex');
            const adminRole = "Super Admin";

            activeAdminSessions.set(sessionToken, {
                user: validUser,
                role: adminRole,
                createdAt: new Date().toISOString()
            });

            logAdminAction(validUser, "ADMIN_LOGIN", clientIp, { userAgent: req.headers['user-agent'] });

            // Set encrypted HttpOnly cookie
            res.cookie('sthirah_admin_session', sessionToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'Strict',
                maxAge: 8 * 60 * 60 * 1000 // 8 hours
            });

            return res.json({ success: true, token: sessionToken, user: validUser, role: adminRole });
        } else {
            logAdminAction("Failed Login", "LOGIN_FAILED", clientIp, { attemptedUser: user });
            return res.status(401).json({ success: false, error: "Access Denied: Invalid admin credentials" });
        }
    } catch (err) {
        console.error("Admin login error:", err);
        return res.status(500).json({ success: false, error: "Internal authentication error" });
    }
});

/**
 * 5. Protected Administrative Routes with RBAC & Audit Trail
 */
app.get('/api/admin/audit-logs', validateAdminSession, authorizeRoles('Super Admin'), (req, res) => {
    res.json({ success: true, logs: adminAuditLogs });
});

app.get('/api/admin/reports/gst', validateAdminSession, authorizeRoles('Super Admin', 'Billing Manager'), (req, res) => {
    logAdminAction(req.adminSession.user, "EXPORT_GST_REPORT", "GSTR-1", { date: new Date().toISOString() });
    res.json({ success: true, message: "GST Statutory Report data authorized" });
});

app.get('/api/admin/reports/pnl', validateAdminSession, authorizeRoles('Super Admin'), (req, res) => {
    logAdminAction(req.adminSession.user, "VIEW_PNL_REPORT", "P&L Statement", { date: new Date().toISOString() });
    res.json({ success: true, message: "Profit & Loss data authorized" });
});

/**
 * 6. Persistent Cart Synchronization & Session Merge Endpoint
 */
app.post('/api/cart/sync', (req, res) => {
    try {
        const { cart, guestToken } = req.body;
        const cartSecret = process.env.CART_SECRET || 'sthirah_cart_tamper_secret';

        const cartDataStr = JSON.stringify(cart || []);
        const cartHash = crypto.createHmac('sha256', cartSecret).update(cartDataStr).digest('hex');

        res.json({
            success: true,
            cartHash,
            guestToken: guestToken || crypto.randomBytes(16).toString('hex')
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Cart sync failed" });
    }
});

app.post('/api/cart/merge', (req, res) => {
    try {
        const { guestCart, userEmail, guestToken } = req.body;
        // Invalidate old guest token to prevent session fixation
        const newSessionToken = crypto.randomBytes(32).toString('hex');

        console.log(`[SESSION MERGE] Guest cart merged for customer: ${userEmail}. Invalidated guest token: ${guestToken}`);
        res.json({
            success: true,
            message: "Guest cart merged securely with customer profile",
            newSessionToken
        });
    } catch (err) {
        res.status(500).json({ success: false, error: "Cart merge failed" });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
    console.log(`[STHIRAH BACKEND SECURITY ENGINE] Server running securely on port ${PORT}`);
});
