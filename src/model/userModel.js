import mongoose from "mongoose";

const { Schema, model } = mongoose;

const usersData = new Schema({
  userData: [
    {
      name: String,
      email: String,
      image: String,
      username: String,
      password: String,
      verification: Boolean,
      resetToken: String || Number,
      resetTokenExpiry: String || Number,
      verificationToken: String || Number,
      expiresAt: String || Number,
      role:String,
      dashusername:String,
      dashpassword:String,
    },
  ],
});

const UserModel = model("User", usersData);

export default UserModel; // Use ES module export
