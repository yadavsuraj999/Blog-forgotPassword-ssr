const mongoose = require("mongoose");


const userSchema = new mongoose.Schema({
    userName:{
        type: String,
        required:true
    },
    userEmail:{
        type: String,
        required:true,
        match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        unique: true,
        lowercase: true,
    },
    userPassword:{
        type:String,
        required:true,
        minlength:6,
    },
    forgotPasswordOtp:{
        type: String,
    },
    otpExp: {
        type: Date,
    }
})

const UserModel = mongoose.model("UserModel", userSchema);

module.exports = UserModel;