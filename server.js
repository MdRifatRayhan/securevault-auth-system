const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const csurf = require("csurf");
const cookieParser = require("cookie-parser");

const app = express();

app.use(express.json());
app.use(cookieParser());

const csrfProtection = csurf({ cookie: true });
const SECRET = "mysecretkey";

/* DB */
mongoose.connect("mongodb+srv://admin:fI27hhJbWUQhh9XQ@cluster0.cw6dvem.mongodb.net/securevault?retryWrites=true&w=majority")
.then(()=>console.log("MongoDB Connected"))
.catch(err=>console.log(err));

/* MODEL */
const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
  resetToken: String   // ✅ NEW
});

/* TEMP */
let currentOTP = "";

/* CSRF */
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/* REGISTER */
app.post("/api/register", csrfProtection, async (req, res) => {
  const { username, email, password } = req.body;

  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hash });

  res.json({ success: true, message: "Registered" });
});

/* LOGIN */
app.post("/api/login", csrfProtection, async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (!user) return res.json({ success: false, message: "User not found" });

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) return res.json({ success: false, message: "Wrong password" });

  currentOTP = Math.floor(100000 + Math.random() * 900000).toString();
  console.log("OTP:", currentOTP);

  res.json({ success: true, message: "OTP sent" });
});

/* VERIFY OTP */
app.post("/api/verify-otp", csrfProtection, (req, res) => {
  const { otp } = req.body;

  console.log("Entered OTP:", otp);

  if (otp === currentOTP) {
    const token = jwt.sign({ user: "demo" }, SECRET);

    return res.json({
      success: true,
      message: "Login successful",
      token: token
    });
  }

  res.json({ success: false, message: "Wrong OTP" });
});

/* 🔥 FIXED FORGOT PASSWORD */
app.post("/api/forgot-password", csrfProtection, async (req, res) => {
  const { username } = req.body;

  const user = await User.findOne({ username });

  if (!user) {
    return res.json({ success: false, message: "User not found" });
  }

  const token = Math.random().toString(36).substring(2);

  user.resetToken = token;
  await user.save();

  console.log("Reset Token:", token);

  res.json({ success: true, message: "Reset token generated" });
});

/* 🔥 FIXED RESET PASSWORD */
app.post("/api/reset-password", csrfProtection, async (req, res) => {
  const { token, newPassword } = req.body;

  console.log("Reset request:", token);

  const user = await User.findOne({ resetToken: token });

  if (!user) {
    return res.json({
      success: false,
      message: "Invalid token"
    });
  }

  if (!newPassword || newPassword.length < 8) {
    return res.json({
      success: false,
      message: "Password must be at least 8 characters"
    });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  user.password = hashedPassword;
  user.resetToken = null;

  await user.save();

  res.json({
    success: true,
    message: "Password reset successful"
  });
});

/* STATIC */
app.use(express.static(__dirname));

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});