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
mongoose.connect("mongodb+srv://admin:<fI27hhJbWUQhh9XQ>@cluster0.cw6dvem.mongodb.net/?appName=Cluster0")
.then(()=>console.log("MongoDB Connected"))
.catch(err=>console.log(err));

/* MODEL */
const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String
});

/* TEMP */
let currentOTP = "";
let resetToken = "";

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

  // ✅ RANDOM OTP
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

/* FORGOT PASSWORD */
app.post("/api/forgot-password", csrfProtection, (req, res) => {
  const { email } = req.body;

  resetToken = Math.random().toString(36).substring(2);
  console.log("Reset Token:", resetToken);

  res.json({ success: true, message: "Check terminal for reset token" });
});
app.post("/api/reset-password", csrfProtection, async (req, res) => {
  const { token, newPassword } = req.body;

  console.log("Reset request:", token, newPassword); // DEBUG

  if (token !== resetToken) {
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

  // ✅ HASHING হচ্ছে এখানে
  const hashedPassword = await bcrypt.hash(newPassword, 10);

  await User.updateOne(
    { username: "demo" },
    { password: hashedPassword }
  );

  resetToken = "";

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