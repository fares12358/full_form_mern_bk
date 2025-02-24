import dotenv from "dotenv";
dotenv.config();

const API_SECRET = process.env.API_SECRET_TOKEN;

const authenticateToken = (req, res, next) => {
    const excludedRoutes = [
        "/verifyEmail",
        "/verify"
        ]; // Skip authentication for these routes

    if (excludedRoutes.includes(req.path)) {
        return next(); // Skip auth for this request
    }
    if (req.path.startsWith("/reset-password")) {
        return next(); // Skip authentication
    }
    const token = req.headers["authorization"];

    if (!token) {
        return res.status(403).json({ message: "Forbidden: Missing token" });
    }

    const tokenParts = token.split(" ");
    if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer" || tokenParts[1] !== API_SECRET) {
        return res.status(403).json({ message: "Forbidden: Invalid token" });
    }

    next();
};

export default authenticateToken;
