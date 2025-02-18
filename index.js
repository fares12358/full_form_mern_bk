const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const app = express();
const UserModel = require('./model/userModel');
const db = mongoose.connection;
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const bodyParser = require("body-parser");
const path = require("path");
require('dotenv').config();

const PORT = 5000;
const API_URL = process.env.API_URL||"http://localhost:5000";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.nodemailer_user, // Replace with your email
    pass: process.env.nodemailer_pass // Replace with your email password
  }
});

app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));


// Connect to MongoDB (Replace with your credentials)
mongoose.connect(`${process.env.db_connection}`);

db.on("error", console.error.bind(console, "MongoDB connection error:"));
db.once("open", () => console.log("Connected to MongoDB"));



// Home Route
app.get("/", (req, res) => {
  res.send("Hello, Node.js with Express!");
});

// Get All Users (Now Fetching from MongoDB)

app.get("/users", async (req, res) => {
  try {
    const users = await UserModel.find();
    res.status(200).json({ users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});


app.post("/google-login", async (req, res) => {
  try {
    const { name, email, image } = req.body;
    console.log('login proces start');

    if (!name || !email || !image) {
      res.status(400).json({ message: "image/name/email required" });
    }

    // Check if a user with the given email already exists
    const existingUser = await UserModel.findOne({ "userData.email": email });


    if (existingUser) {
      // If the user exists, update their information without removing any other data
      const updatedUser = await UserModel.findOneAndUpdate(
        { "userData.email": email },
        {
          $set: {
            "userData.$.name": name,
            "userData.$.email": email,
            "userData.$.image": image,
          }
        },
        { new: true }
      );

      return res.status(200).json({ message: "User updated successfully" });
    } else {
      // If the user does not exist, create a new user
      const newUser = { name, email, image, verification: true };

      const userDoc = await UserModel.findOneAndUpdate(
        {}, // Empty filter to match any document
        { $push: { userData: newUser } },
        { new: true, upsert: true } // Create a new document if none exists
      );
      return res.status(200).json({ message: "User created successfully" });
    }

  } catch (error) {
    res.status(404).json({ message: "Error creating/updating user", error });
  }
});

app.post("/Login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Username and password are required" });
    }

    // Find user by username
    const existingUser = await UserModel.findOne({ "userData.username": username });

    if (!existingUser) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = existingUser.userData.find(user => user.username === username);


    if (!user) {
      return res.status(404).json({ message: "User not found in userData" });
    }

    // Compare hashed password with provided password
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

app.post("/getUserData", async (req, res) => {
  try {
    const { email, isVr } = req.body;

    if (!email || !isVr) {
      return res.status(400).json({ message: "Email and isVr are required" });
    }

    // Find the document that contains the user
    const existingUser = await UserModel.findOne({ "userData.email": email });

    if (!existingUser) {
      return res.status(404).json({ message: "Cannot find user with this email" });
    }

    // Extract the specific user from the userData array
    const user = existingUser.userData.find(user => user.email === email);

    if (!user) {
      return res.status(404).json({ message: "User not found in userData" });
    }
    console.log(user);

    return res.status(200).json(user);

  } catch (error) {
    return res.status(500).json({ message: "Error in API", error: error.message });
  }
});

app.post('/CreateAcc', async (req, res) => {
  try {
    const { name, username, password, email } = req.body; // Get username, password, and name from request

    if (!name || !username || !password || !email) {
      return res.status(240).json({ message: "Name, username, and password are required" });
    }

    // Check if user already exists
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
            verification: false
          }
        }
      },
      { new: true, upsert: true }
    );

    // Get only the newly created user
    const newUser = updatedUser.userData.find(user => user.username === username);

    res.status(201).json({ message: "Verification email sent. Please check your inbox.", user: newUser });
  } catch (error) {
    console.error("Error creating account:", error);
    res.status(500).json({ message: "Internal server error", error: error.message });
  }
});

app.get("/verify", async (req, res) => {
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

    const decoded = jwt.verify(token, process.env.jwt_secret_key);
    const user = await UserModel.findOneAndUpdate(
      { "userData.email": decoded.email },
      { $set: { "userData.$.verification": true } },
      { new: true }
    );

    if (!user) {
      return res.status(400).send(`
        <html>
          <body style="text-align:center; font-family:Arial; padding:50px;">
            <h2 style="color:red;">User not found</h2>
          </body>
        </html>
      `);
    }

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


app.post('/forgot-password', async (req, res) => {
  try {
    const { identifier } = req.body; // Accept username or email

    if (!identifier) {
      return res.status(400).json({ message: "Username or email is required" });
    }

    // Find user by username or email
    const user = await UserModel.findOne({
      $or: [
        { "userData.username": identifier },
        { "userData.email": identifier }
      ]
    });

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // If userData is an array, find the correct entry
    let targetUser;
    if (Array.isArray(user.userData)) {
      targetUser = user.userData.find(u => u.username === identifier || u.email === identifier);
    } else {
      targetUser = user.userData; // If it's an object, use it directly
    }

    if (!targetUser) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    targetUser.resetToken = resetToken;
    targetUser.resetTokenExpiry = Date.now() + 3600000; // 1 hour expiration

    // If userData is an array, update the main user document
    if (Array.isArray(user.userData)) {
      user.userData = user.userData.map(u => 
        u.username === identifier || u.email === identifier ? targetUser : u
      );
    }

    // Save the updated user document
    await user.save();

    // Send reset email
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


app.get("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;

    // Check if the token is valid
    const userDoc = await UserModel.findOne({
      userData: {
        $elemMatch: { resetToken: token, resetTokenExpiry: { $gt: Date.now() } },
      },
    });

    if (!userDoc) {
      return res.status(400).send("<h2>Invalid or expired reset token</h2>");
    }

    // Serve an HTML form for password reset
    res.sendFile(path.join(__dirname, "/reset-password.html"));
  } catch (error) {
    res.status(500).send("<h2>Server error</h2>");
  }
});

// Handle password reset form submission
app.post("/reset-password/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).send("<h2>Password must be at least 6 characters long</h2>");
    }

    // Find user inside the userData array
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

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update user password and clear reset token
    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    // Save the updated document
    await userDoc.save();

    res.send("<h2>Password reset successful! You can now log in.</h2>");
  } catch (error) {
    res.status(500).send("<h2>Server error</h2>");
  }
});











app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
