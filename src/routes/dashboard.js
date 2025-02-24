import { Router } from "express";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import UserModel from "../model/userModel.js";
import { transporter } from "../utils/nodemailer.js";
dotenv.config();
const router = Router();


router.post('/dashLogin', async (req, res) => {
    try {
        const { username, password } = req.body
        if (!username || !password) {
            return res.status(400).json({ message: "Username and password is required" });
        }
        const existingUser = await UserModel.findOne({ "userData.dashusername": username });
        if (!existingUser) {
            return res.status(404).json({ message: "User not found" });
        }
        const user = existingUser.userData.find(user => user.dashusername === username);
        if (!user) {
            return res.status(404).json({ message: "User not found in userData" });
        }
        const isPasswordValid = await bcrypt.compare(password, user.dashpassword);
        if (!isPasswordValid) {
            return res.status(404).json({ message: "Invalid password or username", login: false });
        }
        res.status(200).json({ message: "Login successful", user: user, login: true });

    } catch (error) {
        res.status(500).json({ message: "Internal server error", error: error.message, login: false });
    }
})


router.post("/dashGetPass", async (req, res) => {
    try {
        // Find the admin user
        const existingUser = await UserModel.findOne({ "userData.role": "admin" });

        if (!existingUser) {
            return res.status(404).json({ message: "Admin not found" });
        }

        const adminUser = existingUser.userData.find(user => user.role === "admin");

        if (!adminUser) {
            return res.status(404).json({ message: "Admin not found" });
        }

        // Generate a new temporary password
        const newPass = Math.random().toString(36).slice(-8); // Generate a random 8-character password
        const hashedPass = await bcrypt.hash(newPass, 10); // Hash the new password

        // Update the password in the database
        await UserModel.updateOne(
            { "userData._id": adminUser._id },
            { $set: { "userData.$.dashpassword": hashedPass } }
        );

        // Send email with the new password
        await transporter.sendMail({
            from: "YKSTOR.com",
            to: adminUser.email,
            subject: "Your New dashboard Password",
            text: `Your new password is: ${newPass}\n\nPlease change it after logging in.`,
        });

        return res.status(200).json({ message: "New password sent successfully ,Chick your email" });

    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error: error.message });
    }
});





export default router;