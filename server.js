const express = require("express");
const bcrypt = require("bcrypt");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const csurf = require("csurf");
const cookieParser = require("cookie-parser");
const xss = require("xss");

const app = express();

app.use(express.json());
app.use(cookieParser());

const csrfProtection = csurf({ cookie: true });
const SECRET = "mysecretkey";

function auth(req, res, next) {

  const token = req.headers.authorization;

  if (!token) {
    return res.json({
      success: false,
      message: "Access denied"
    });
  }

  try {

   const decoded =
jwt.verify(token, SECRET);

req.user = decoded.user;

next();

  } catch {

    res.json({
      success: false,
      message: "Invalid token"
    });
  }
}

/* DB */
mongoose.connect("mongodb+srv://admin:fI27hhJbWUQhh9XQ@cluster0.cw6dvem.mongodb.net/securevault?retryWrites=true&w=majority")
.then(()=>console.log("MongoDB Connected"))
.catch(err=>console.log(err));

/* MODEL */
const User = mongoose.model("User", {
  username: String,
  email: String,
  password: String,
  resetToken: String,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Number, default: 0 },
  lastLogin: String
});

/* TEMP */
let currentOTP = "";
let otpTime = 0;
let otpUser = "";// 🔥 track current user
let otpAttempts = 0;

/* CSRF */
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

/* REGISTER */
app.post("/api/register", csrfProtection, async (req, res) => {
  let { username, email, password } = req.body;

  username = xss(username);
  email = xss(email);
  password = xss(password);

  if (!username || !password) {
    return res.json({ success: false, message: "All fields required" });
  }

  const existing = await User.findOne({ username });

  if (existing) {
    return res.json({ success: false, message: "Username already exists" });
  }

  const strongPassword =
/^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#]).{8,}$/;

if (!strongPassword.test(password)) {
  return res.json({
    success: false,
    message:
    "Password must contain 8 characters, 1 uppercase letter, 1 number and 1 special character"
  });
}

  const hash = await bcrypt.hash(password, 10);
  await User.create({ username, email, password: hash });

  res.json({ success: true, message: "Registered" });
});

/* LOGIN */
app.post("/api/login", csrfProtection, async (req, res) => {
  let { username, password } = req.body;

  username = xss(username);
  password = xss(password);

  if (!username || !password) {
    return res.json({ success: false, message: "All fields required" });
  }

  const user = await User.findOne({ username });

  if (!user) {
    return res.json({ success: false, message: "User not found" });
  }

  if (user.lockUntil && user.lockUntil > Date.now()) {
    return res.json({
      success: false,
      message: "Account locked. Try again later"
    });
  }

  const ok = await bcrypt.compare(password, user.password);

  if (!ok) {
    user.loginAttempts += 1;
    let attemptsLeft = 3 - user.loginAttempts;

    if (user.loginAttempts >= 3) {
      user.lockUntil = Date.now() + 5 * 60 * 1000;
      user.loginAttempts = 0;

      await user.save();

      return res.json({
        success: false,
        message: "Account locked for 5 minutes"
      });
    }

    await user.save();

    return res.json({
      success: false,
      message: attemptsLeft + " attempts left"
    });
  }

  user.loginAttempts = 0;

user.lockUntil = 0;

user.lastLogin =
new Date().toLocaleString();

await user.save();

  currentOTP =
Math.floor(100000 + Math.random() * 900000).toString();

otpTime = Date.now();

otpUser = username;

otpAttempts = 0;

  console.log("OTP:", currentOTP);

  res.json({ success: true, message: "OTP sent" });
});

/* 🔥 RESEND OTP */
app.post("/api/resend-otp", csrfProtection, (req, res) => {

 if (!otpUser) {
  return res.json({
    success: false,
    message: "Login first"
  });
}

  currentOTP =
Math.floor(100000 + Math.random() * 900000).toString();

otpTime = Date.now();

otpAttempts = 0;

  console.log("Resent OTP:", currentOTP);

  res.json({ success: true, message: "OTP resent" });
});

/* VERIFY OTP */
app.post("/api/verify-otp", csrfProtection, (req, res) => {
  const { otp } = req.body;

  if (!otpTime || Date.now() - otpTime > 45000) {
    return res.json({ success: false, message: "OTP expired" });
  }

  if (otp !== currentOTP) {

  otpAttempts++;

  if (otpAttempts >= 3) {

    currentOTP = "";
    otpTime = 0;
    otpUser = "";
    otpAttempts = 0;

    return res.json({
      success: false,
      message:
      "Too many wrong OTP attempts. Login again."
    });
  }

  return res.json({
    success: false,
    message:
    "Wrong OTP. Attempts left: " +
    (3 - otpAttempts)
  });
}

  if (otp === currentOTP) {

    const token = jwt.sign(
  { user: otpUser },
  SECRET
);

currentOTP = "";
otpTime = 0;
otpUser = "";
otpAttempts = 0;

    return res.json({
      success: true,
      message: "Login successful",
      token: token
    });
  }


});

/* FORGOT PASSWORD */
app.post("/api/forgot-password", csrfProtection, async (req, res) => {
  let { username } = req.body;

  username = xss(username);

  if (!username) {
    return res.json({ success: false, message: "Enter username" });
  }

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

/* RESET PASSWORD */
app.post("/api/reset-password", csrfProtection, async (req, res) => {
  let { token, newPassword } = req.body;

  token = xss(token);
  newPassword = xss(newPassword);

  const user = await User.findOne({ resetToken: token });

  if (!user) {
    return res.json({ success: false, message: "Invalid token" });
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

  res.json({ success: true, message: "Password reset successful" });
});

app.get("/api/profile", auth, async (req, res) => {

  const user =
  await User.findOne({
    username: req.user
  });

  res.json({

    success: true,

    message:
    "Welcome, " + req.user,

    lastLogin:
    user.lastLogin

  });

});

app.use(express.static(__dirname));

app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
