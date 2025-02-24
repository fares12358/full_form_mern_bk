import { Router } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";
import rateLimit from 'express-rate-limit';
import UserModel from "../model/userModel.js";
import { transporter } from "../utils/nodemailer.js";
import dotenv from "dotenv";
dotenv.config();
const router = Router();
const API_URL = process.env.API_URL || "http://localhost:5000";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: "Too many login attempts, please try again later." },
});
router.post("/google-login", async (req, res) => {
    try {
        const { name, email, image } = req.body;

        if (!name || !email || !image) {
            return res.status(400).json({ message: "image/name/email required" });
        }

        const existingUser = await UserModel.findOne({ "userData.email": email });

        if (existingUser) {
            return res.status(200).json({ message: "User already exists", user: existingUser });
        } else {
            const newUser = { name, email, image, verification: true };

            const userDoc = await UserModel.findOneAndUpdate(
                {}, // Find any document (assuming a single document structure)
                { $push: { userData: newUser } },
                { new: true, upsert: true } // Ensure a document exists, create one if necessary
            );

            return res.status(200).json({ message: "User created successfully", user: newUser });
        }
    } catch (error) {
        res.status(500).json({ message: "Error processing request", error });
    }
});

router.post("/Login", loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: "Username and password are required" });
        }
        const existingUser = await UserModel.findOne({ "userData.username": username });
        if (!existingUser) {
            return res.status(404).json({ message: "User not found" });
        }
        const user = existingUser.userData.find(user => user.username === username);
        if (!user) {
            return res.status(404).json({ message: "User not found in userData" });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: "Invalid password or username", login: false });
        }
        res.status(200).json({ message: "Login successful", user: user, login: true });
    } catch (error) {
        console.error("Error logging in:", error);
        res.status(500).json({ message: "Internal server error", error: error.message, login: false });
    }
});

router.post('/CreateAcc', async (req, res) => {
    try {
        const { name, username, password, email } = req.body;
        if (!name || !username || !password || !email) {
            return res.status(240).json({ message: "Name, username, and password are required" });
        }
        const existingUser = await UserModel.findOne({ "userData.username": username });
        const existingEmail = await UserModel.findOne({ "userData.email": email });
        if (existingUser) {
            return res.status(400).json({ message: "Username already exists" });
        }
        if (existingEmail) {
            return res.status(400).json({ message: "Email already exists" });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const verificationToken = jwt.sign({ email }, process.env.jwt_secret_key, { expiresIn: "1h" });
        const verificationLink = `${API_URL}/verify?token=${verificationToken}`;
        await transporter.sendMail({
            from: "YKSTOR.com",
            to: email,
            subject: "Verify Your Email",
            text: `Click the link to verify your account: ${verificationLink}`
        });

        const updatedUser = await UserModel.findOneAndUpdate(
            {},
            {
                $push: {
                    userData: {
                        name,
                        username,
                        password: hashedPassword,
                        email,
                        verification: false,
                        verificationToken,
                        expiresAt: Date.now() + 3600000
                    }
                }
            },
            { new: true, upsert: true }
        );
        const newUser = updatedUser.userData.find(user => user.username === username);
        res.status(201).json({ message: "Verification email sent. Please check your inbox.", user: newUser });
    } catch (error) {
        console.error("Error creating account:", error);
        res.status(500).json({ message: "Internal server error", error: error.message });
    }
});
router.get("/verify", async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) {
            return res.status(400).send(`
            <html>
              <body style="text-align:center; font-family:Arial; padding:50px;">
                <h2 style="color:red;">Invalid token</h2>
              </body>
            </html>
          `);
        }

        // Verify JWT token
        const decoded = jwt.verify(token, process.env.jwt_secret_key);

        // Find user with matching email and token
        const user = await UserModel.findOne({
            "userData.email": decoded.email,
            "userData.verificationToken": token
        });

        if (!user) {
            return res.status(400).send(`
            <html>
              <body style="text-align:center; font-family:Arial; padding:50px;">
                <h2 style="color:red;">User not found or invalid token</h2>
              </body>
            </html>
          `);
        }

        // Find the exact user entry
        const userEntry = user.userData.find(u => u.email === decoded.email);

        // Check if the token has expired
        if (!userEntry || Date.now() > userEntry.expiresAt) {
            return res.status(400).send(`
            <html>
              <body style="text-align:center; font-family:Arial; padding:50px;">
                <h2 style="color:red;">Token has expired</h2>
              </body>
            </html>
          `);
        }

        // Update verification status and remove token
        await UserModel.updateOne(
            { "userData.email": decoded.email },
            {
                $set: { "userData.$[elem].verification": true },
                $unset: { "userData.$[elem].verificationToken": "", "userData.$[elem].expiresAt": "" }
            },
            { arrayFilters: [{ "elem.email": decoded.email }] }
        );

        res.send(`
        <html>
          <body style="text-align:center; font-family:Arial; padding:50px;">
            <h2 style="color:green;">Email verified successfully</h2>
          </body>
        </html>
      `);
    } catch (error) {
        res.status(400).send(`
        <html>
          <body style="text-align:center; font-family:Arial; padding:50px;">
            <h2 style="color:red;">Invalid or expired token</h2>
          </body>
        </html>
      `);
    }
});
router.post('/forgot-password', async (req, res) => {
    try {
        const { identifier } = req.body;
        if (!identifier) {
            return res.status(400).json({ message: "Username or email is required" });
        }
        const user = await UserModel.findOne({
            $or: [
                { "userData.username": identifier },
                { "userData.email": identifier }
            ]
        });
        if (!user) {
            return res.status(400).json({ message: 'User not found' });
        }
        let targetUser;
        if (Array.isArray(user.userData)) {
            targetUser = user.userData.find(u => u.username === identifier || u.email === identifier);
        } else {
            targetUser = user.userData;
        }
        if (!targetUser) {
            return res.status(400).json({ message: 'User not found' });
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        targetUser.resetToken = resetToken;
        targetUser.resetTokenExpiry = Date.now() + 3600000;
        if (Array.isArray(user.userData)) {
            user.userData = user.userData.map(u =>
                u.username === identifier || u.email === identifier ? targetUser : u
            );
        }
        await user.save();
        const resetLink = `${API_URL}/reset-password/${resetToken}`;
        await transporter.sendMail({
            from: "YKSTOR.com",
            to: targetUser.email,
            subject: "Password Reset Request",
            text: `Click the link to reset your password: ${resetLink}`
        });
        res.status(200).json({ message: 'Password reset link sent , Please check your inbox.' });
    } catch (error) {
        res.status(500).json({ message: 'Server error', error });
    }
});
router.get("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const userDoc = await UserModel.findOne({
            userData: {
                $elemMatch: { resetToken: token, resetTokenExpiry: { $gt: Date.now() } },
            },
        });
        if (!userDoc) {
            return res.status(400).send("<h2>Invalid or expired reset token</h2>");
        }
        console.log("Serving file from:", path.resolve(__dirname, "../utils/reset-password.html"));
        res.sendFile(path.join(__dirname, "../utils/reset-password.html"));
    } catch (error) {
        res.status(500).send("<h2>Server error api</h2>");
    }
});
router.post("/reset-password/:token", async (req, res) => {
    try {
        const { token } = req.params;
        const { newPassword } = req.body;
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).send("<h2>Password rquiered must be at least 6 characters long</h2>");
        }
        const userDoc = await UserModel.findOne({
            userData: {
                $elemMatch: { resetToken: token, resetTokenExpiry: { $gt: Date.now() } },
            },
        });
        if (!userDoc) {
            return res.status(400).send("<h2>Invalid or expired token</h2>");
        }
        const user = userDoc.userData.find((u) => u.resetToken === token);
        if (!user) {
            return res.status(400).send("<h2>User not found</h2>");
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiry = undefined;
        await userDoc.save();
        res.send("<h2>Password reset successful! You can now log in.</h2>");
    } catch (error) {
        res.status(500).send("<h2>Server error</h2>");
    }
});

export default router;