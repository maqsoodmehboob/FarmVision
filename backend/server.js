const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

/* =========================
   Middleware
========================= */
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =========================
   MongoDB Connection
========================= */
const ATLAS_URI = process.env.MONGO_URI || "mongodb://127.0.0.1:27017/farmvision";

mongoose.connect(ATLAS_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
  family: 4,
}).then(() => console.log("✅ MongoDB Atlas connected"))
  .catch((err) => console.error("❌ MongoDB error:", err.message));

/* =========================
   User Schema
========================= */
const userSchema = new mongoose.Schema({
  name:         { type: String, required: true, trim: true },
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  createdAt:    { type: Date, default: Date.now },
});
const User = mongoose.model("User", userSchema);

/* =========================
   Scan History Schema ← NEW
========================= */
const scanSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  crop:       { type: String, required: true },
  disease:    { type: String, required: true },
  confidence: { type: Number },
  cause:      { type: String },
  prevention: { type: String },
  treatment:  { type: String },
  weather:    { type: Object },
  imageUri:   { type: String },
  mode:       { type: String },
  createdAt:  { type: Date, default: Date.now },
});
const Scan = mongoose.model("Scan", scanSchema);

/* =========================
   JWT Config
========================= */
const JWT_SECRET = process.env.JWT_SECRET || "farmvision-super-secret-key-2025";

/* =========================
   Auth Middleware
========================= */
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid token" });
  }
};

/* =========================
   Test Route
========================= */
app.get("/", (req, res) => {
  res.json({ message: "Farm Vision API running successfully" });
});

/* =========================
   SIGNUP ROUTE
========================= */
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ message: "Email already registered" });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, passwordHash });
    await newUser.save();

    res.status(201).json({
      message: "User registered successfully",
      user: { id: newUser._id, name: newUser.name, email: newUser.email },
    });
  } catch (error) {
    console.error("SIGNUP ERROR:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   LOGIN ROUTE
========================= */
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(400).json({ message: "Invalid credentials" });

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   SAVE SCAN HISTORY ← NEW
========================= */
app.post("/api/history/save", authMiddleware, async (req, res) => {
  try {
    const {
      crop, disease, confidence, cause,
      prevention, treatment, weather, imageUri, mode
    } = req.body;

    const scan = new Scan({
      userId:     req.userId,
      crop, disease, confidence,
      cause, prevention, treatment,
      weather, imageUri, mode,
    });

    await scan.save();
    res.status(201).json({ message: "Scan saved", scan });
  } catch (error) {
    console.error("SAVE SCAN ERROR:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   GET SCAN HISTORY ← NEW
========================= */
app.get("/api/history", authMiddleware, async (req, res) => {
  try {
    const scans = await Scan.find({ userId: req.userId })
      .sort({ createdAt: -1 })  // Latest first
      .limit(50);                // Max 50 records

    res.json({ scans });
  } catch (error) {
    console.error("GET HISTORY ERROR:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   DELETE SCAN ← NEW
========================= */
app.delete("/api/history/:id", authMiddleware, async (req, res) => {
  try {
    await Scan.findOneAndDelete({
      _id: req.params.id,
      userId: req.userId,
    });
    res.json({ message: "Scan deleted" });
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

/* =========================
   Server Start
========================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});