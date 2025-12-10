import jwt from "jsonwebtoken";

export const auth = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization; // Bearer token
    if (!authHeader) {
      return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "Invalid token format" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // { id, email }
    next();
  } catch (err) {
    console.error("Auth middleware error:", err.message);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};
