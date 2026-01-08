const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const UserModel = require("../models/userModle")

const getSignUp = (req, res) => {
    return res.render("signup")
}

const getSignIn = (req, res) => {
    return res.render("signin")
}

const signUpUser = async (req, res) => {
    try {
        const { userName, userEmail, userPassword } = req.body
        const hashedPassword = await bcrypt.hash(userPassword, 10);
        const userData = new UserModel({
            userName, userEmail, userPassword: hashedPassword
        })
        await userData.save();
        res.redirect("/auth/signin");
    } catch (error) {
        console.log(error)
    }
}

const signinUser = async (req, res) => {
    try {
        const { userEmail, userPassword } = req.body;
        const loginUser = await UserModel.findOne({ userEmail })
        console.log(loginUser)
        if (!loginUser) {
            return res.send("Invalid Email or Password");
        }

        const isMatch = await bcrypt.compare(userPassword, loginUser.userPassword);

        if (!isMatch) {
            return res.send("Invalid Email or Password");
        }

        const token = jwt.sign({
            id: loginUser._id
        }, process.env.JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.cookie("check", token, {
            maxAge: 24 * 60 * 60 * 1000,
            httpOnly: true
        });

        res.redirect("/admin/view-blog");
    } catch (error) {
        console.log(error);
    }
}
const logOut = (req, res) => {
    res.clearCookie("check");
    res.redirect("/");
}

module.exports = { getSignUp, getSignIn, signUpUser, signinUser, logOut }