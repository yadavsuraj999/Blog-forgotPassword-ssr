const express = require("express");
const {
  getSignUp,
  getSignIn,
  signUpUser,
  signinUser,
  logOut
} = require("../controllers/authController");

const UserModel = require("../models/userModle");
const router = express.Router();
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

router.get("/signin", getSignIn);
router.get("/signup", getSignUp);
router.get("/forgot-password", (req, res) => {
  res.render("forgotPassword");
});
router.get("/log-out", logOut);
router.get("/reset-password", (req, res) => {
  return res.render("resetPassword")
});

router.post("/signup", signUpUser);
router.post("/signin", signinUser);
router.post("/forgot-password", async (req, res) => {
  try {
    const { userEmail } = req.body;

    const user = await UserModel.findOne({ userEmail });
    if (!user) {
      return res.status(404).send("User not found");
    }

    const OTP = parseInt(100000 + Math.random() * 900000).toString();
    const hashOtp = await bcrypt.hash(OTP, 10);
    console.log(OTP, hashOtp);

    user.forgotPasswordOtp = hashOtp;
    user.otpExp = Date.now() + 10 * 60 * 1000;
    await user.save();


    const suraj = async (userEmail, OTP) => {
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.ADMIN_EMAIL,
          pass: process.env.ADMIN_PASS,
        },
      });
      await transporter.sendMail({
        from: process.env.ADMIN_EMAIL,
        to: userEmail,
        subject: "OTP for Reset Password",
        html: `<!DOCTYPE html>
      <html lang="en">
      <head>
      <meta charset="UTF-8">
      <title>Email Verification</title>
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <style>
      body {
        margin: 0;
      padding: 0;
      background-color: #f4f6f8;
      font-family: Arial, sans-serif;
      }
      .container {
        max-width: 500px;
        margin: 40px auto;
        background: #ffffff;
        border-radius: 8px;
        overflow: hidden;
        box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        .header {
          background: #4f46e5;
          color: #ffffff;
          text-align: center;
          padding: 20px;
          font-size: 22px;
          font-weight: bold;
          }
          .content {
            padding: 30px;
            text-align: center;
            }
            .content p {
              font-size: 15px;
              color: #555;
              line-height: 1.6;
              }
              .otp-box {
                margin: 25px auto;
                font-size: 28px;
                letter-spacing: 10px;
                font-weight: bold;
                color: #111;
                background: #f3f4f6;
                padding: 15px 20px;
                border-radius: 6px;
                display: inline-block;
                }
                .footer {
                  padding: 15px;
                  text-align: center;
                  font-size: 12px;
                  color: #888;
                  background: #fafafa;
                  }
                  </style>
                  </head>
                  <body>
                  
                  <div class="container">
                  <div class="header">
                  OTP Verification
                  </div>
                  
                  <div class="content">
                  <p>
                  Use the following One Time Password to reset your password.
                  This OTP is valid for 10 minutes.
                  </p>
                  
                  <div class="otp-box">
                  ${OTP}
                  </div>
                  
                  <p>
                  If you didn’t request this, you can safely ignore this email.
                  </p>
                  </div>
                  
                  <div class="footer">
                  © 2026 Your App Name. All rights reserved.
                  </div>
                  </div>
                  
                  </body>
                  </html>
                  `,
      })
    }

    await suraj(userEmail, OTP)



    res.redirect("/auth/reset-password");
  } catch (error) {
    console.error(error);
    res.status(500).send("Something went wrong");
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { userEmail, otp, newPassword, confirmPassword } = req.body;

    const user = await UserModel.findOne({ userEmail });
    if (!user) {
      return res.send("User not found");
    }

    if (!user.forgotPasswordOtp || !user.otpExp) {
      return res.send("OTP not requested");
    }

    if (user.otpExp < Date.now()) {
      return res.send("OTP expired");
    }

    const validOtp = await bcrypt.compare(otp, user.forgotPasswordOtp);
    if (!validOtp) {
      return res.send("Invalid OTP");
    }

    if (newPassword !== confirmPassword) {
      return res.send("Password and confirm password do not match");
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.userPassword = hashedPassword;
    user.forgotPasswordOtp = null;
    user.otpExp = null;

    await user.save();

    res.redirect("/auth/signin");
  } catch (error) {
    console.log(error);
    res.status(500).send("Something went wrong");
  }
});






module.exports = router;
