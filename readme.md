# Secure JWT & Email OTP Authentication System

This project is a secure backend authentication system built with Node.js and Express. It provides a robust solution for user registration, login, and authorization using JSON Web Tokens (JWT) and enhances security with an email-based One-Time Password (OTP) verification flow.



## 🚀 Features

* **User Registration:** Secure endpoint for new user sign-up with password hashing (using `bcrypt`).
* **User Login:** Endpoint for user login that returns a signed JWT.
* **JWT Authentication:** Protected routes that verify the JWT from the request (e.g., in an `Authorization` header or `httpOnly` cookie).
* **Email OTP Verification:**
    * Generates a time-sensitive OTP for actions like registration verification or password resets.
    * Uses **Nodemailer** and **SMTP** configuration to send the OTP directly to the user's email address.
    * Endpoint to verify the OTP submitted by the user.
* **Environment-Based Configuration:** Securely manages sensitive keys (like `JWT_SECRET` and SMTP credentials) using `.env` files.

## 🛠️ Tech Stack

* **Backend:** Node.js, Express.js
* **Database:** MongoDB (with Mongoose)
* **Authentication:** `jsonwebtoken` (for JWT), `bcryptjs` (for password hashing)
* **Email:** `nodemailer` (for sending OTPs via SMTP)
* **Environment:** `dotenv` (for managing environment variables)



