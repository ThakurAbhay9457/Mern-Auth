// import { verify } from "jsonwebtoken";
import jwt from "jsonwebtoken";
import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {type: String, required: true},
    email: {type: String, required: true, unique: true},
    password: {type: String, required: true},
    verifyOtp: {type: String, default: ''},
    verifyOtpExpireAt: {type: Number, default: 0},
    isAccountVerified: {type: Boolean, default: false},
    resetOtp: {type: String,  default: 0},
    resetOtpExpireAt: {type: Number, deafult: 0}
})

const userModel = mongoose.models.user || mongoose.model('user', userSchema);

export default userModel;