# Sthirah E-Commerce Backend API & Security Configuration

This server module provides secure backend endpoints for **Razorpay Payment Order Creation**, **Cryptographic HMAC Signature Verification**, **Async Webhook Confirmation**, and **Admin Authentication**.

---

## 1. Local Setup Instructions

1. **Navigate to the server directory**:
   ```bash
   cd server
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Configure Environment Variables (`.env`)**:
   Open `.env` and set your Razorpay Live/Test Key credentials obtained from [Razorpay Dashboard](https://dashboard.razorpay.com/):
   ```env
   PORT=5000
   RAZORPAY_KEY_ID=rzp_test_TM9D2mb6BUdPQ6
   RAZORPAY_KEY_SECRET=your_actual_razorpay_secret_here
   RAZORPAY_WEBHOOK_SECRET=your_webhook_secret_here
   ADMIN_USER=Pradheep
   ADMIN_PASS=Sthirah@2026
   ```

4. **Start the API Server**:
   ```bash
   npm start
   ```
   The backend API will run on `http://localhost:5000` and process cryptographic payment verification requests from `index.html`.

---

## 2. API Endpoints Reference

| Endpoint | Method | Description | Security Standard |
| :--- | :--- | :--- | :--- |
| `/api/create-razorpay-order` | `POST` | Calculates authoritative cart amount & creates Razorpay Order | Prevents client-side price tampering |
| `/api/verify-payment` | `POST` | Validates `razorpay_signature` via HMAC-SHA256 | Cryptographic constant-time timing-safe comparison |
| `/api/razorpay-webhook` | `POST` | Listens for `order.paid` events directly from Razorpay | Guarantees fulfillment even if client disconnects |
| `/api/admin-login` | `POST` | Verifies admin credentials | Prevents plaintext credential leakage in JS bundle |

---

## 3. Production Deployment

- **Firebase Cloud Functions**: Wrap `server.js` using `firebase-functions/v2/https` (`onRequest(app)`).
- **Render / Vercel / Node.js Host**: Deploy as a standard Node.js Express web service.
