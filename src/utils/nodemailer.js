import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();
export const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.nodemailer_user,
        pass: process.env.nodemailer_pass,
    },
});