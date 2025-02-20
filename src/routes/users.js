import { Router } from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import UserModel from "../model/userModel.js";
import { transporter } from "../utils/nodemailer.js";
const API_URL = process.env.API_URL || "http://localhost:5000";
const router = Router();

router.get("/users", async (req, res) => {
  try {
    const users = await UserModel.find();
    return res.status(200).json({ users });
  } catch (error) {
    console.error("Error fetching users:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});


router.post("/getUserData", async (req, res) => {
  try {
    const { identifier } = req.body;

    if (!identifier) {
      return res.status(400).json({ message: "Email or ID are required" });
    }

    // Check if identifier is a valid ObjectId
    const isValidObjectId = mongoose.Types.ObjectId.isValid(identifier);

    const existingUser = await UserModel.findOne({
      $or: [
        { "userData.email": identifier },
        isValidObjectId ? { "userData._id": new mongoose.Types.ObjectId(identifier) } : null
      ].filter(Boolean) // Remove null values to avoid invalid query
    });

    if (!existingUser) {
      return res.status(404).json({ message: "Cannot find user with this email or ID" });
    }

    // Find user within userData array
    const user = existingUser.userData.find(user =>
      (isValidObjectId && user._id.toString() === identifier) || user.email === identifier
    );

    if (!user) {
      return res.status(404).json({ message: "User not found in userData" });
    }

    return res.status(200).json(user);
  } catch (error) {
    return res.status(500).json({ message: "Error in API", error: error.message });
  }
});

router.post('/updateUser', async (req, res) => {
  try {
    const { name, username, newPass, oldPass, email, id } = req.body;
    if (!id) {
      return res.status(400).json({ message: "id required" });
    }
    const existingUser = await UserModel.findOne({ "userData._id": id });
    if (!existingUser) {
      return res.status(400).json({ message: "User not found" });
    }

    const userIndex = existingUser.userData.findIndex(user => user._id.toString() === id);
    if (userIndex === -1) {
      return res.status(400).json({ message: "User not found in userData" });
    }
    console.log(userIndex);
    const updateFields = {}; // Store fields to update
    if (name) updateFields[`userData.${userIndex}.name`] = name;
    if (username) {
      const usernameExists = await UserModel.findOne({ "userData.username": username });
      if (usernameExists) {
        return res.status(400).json({ message: "Username already taken. Please choose another one." });
      }
      updateFields[`userData.${userIndex}.username`] = username;
    }
    if (email) {
      updateFields[`userData.${userIndex}.email`] = email;
      updateFields[`userData.${userIndex}.verification`] = false;
      const verificationToken = jwt.sign({ email }, process.env.jwt_secret_key, { expiresIn: "1h" });
      const verificationLink = `${API_URL}/verify?token=${verificationToken}`;
      await transporter.sendMail({
        from: "YKSTOR.com",
        to: email,
        subject: "Verify Your new Email",
        text: `Click the link to verify your account: ${verificationLink}`
      });
      updateFields[`userData.${userIndex}.verificationToken`] = verificationToken;
      updateFields[`userData.${userIndex}.expiresAt`] = Date.now() + 3600000;
    }
    if (newPass) {
      const existingPassword = existingUser.userData[userIndex].password;
      if (existingPassword) {
        if (!oldPass) {
          return res.status(400).json({ message: "Old password is required to set a new password" });
        }
        const isMatch = await bcrypt.compare(oldPass, existingPassword);
        if (!isMatch) {
          return res.status(400).json({ message: "Incorrect old password" });
        }
      }
      updateFields[`userData.${userIndex}.password`] = await bcrypt.hash(newPass, 10);
    }
    const updatedUser = await UserModel.findOneAndUpdate(
      { "userData._id": id },
      { $set: updateFields },
      { new: true }
    );
    return res.status(200).json({ message: "User updated successfully", user: updatedUser.userData[userIndex] });
  } catch (error) {
    console.error("Error creating account:", error);
    res.status(400).json({ message: "Internal server error", error: error.message });
  }
})

export default router;
