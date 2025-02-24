import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import usersRouter from "./routes/users.js";
import formRoter from "./routes/form.js"
import dashRoter from "./routes/dashboard.js"
import authenticateToken from "./middleware/authMiddleware.js";

dotenv.config();
const app = express();
const PORT = 5000;
app.use(express.json());
app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
mongoose.connect(process.env.db_connection);
mongoose.connection.on("error", console.error.bind(console, "MongoDB connection error:"));
mongoose.connection.once("open", () => console.log("Connected to MongoDB"));

app.use(authenticateToken);

app.use( usersRouter);
app.use( formRoter);
app.use( dashRoter);

app.get("/", (req, res) => {
  res.send("Hello, Node.js with Express!");
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});