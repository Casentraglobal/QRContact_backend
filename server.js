import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";

import authRoutes from "./routes/auth.js";

dotenv.config();

const app = express();

app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json());

// routes
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("Auth API running");
});

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
    app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
  })
  .catch((err) => console.error("Mongo error:", err.message));
