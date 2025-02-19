import { Router } from "express";
import UserModel from "../model/userModel.js";
const router = Router();

router.get("/users", async (req, res) => {
  try {
    const users = await UserModel.find();
    res.status(200).json({ users });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

export default router;
