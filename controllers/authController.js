import UserModel from "../models/user"
import otpModel from "../models/otps"
import ErrorHandler from "../utils/errorHandler.js";
import jwt from 'jsonwebtoken';
import bcrypt from "bcryptjs";
import crypto from "crypto"
import sendEmail from "../utils/sendEmail"
import newOTP from 'otp-generators';
import { handleEmail } from "../utils/helpers";

const regexUserName = /^(?!.*\.\.)(?!.*\.$)[^\W][\w.]{0,29}$/;


export const checkPhone = async (req, res, next) => {
    const { phoneNumber } = req.params
    try {

        const user = await UserModel.findOne({ phoneNumber: phoneNumber })

        if (!user) return next(new ErrorHandler("This phone number is not registered", 200))

        return res.status(200).json({
            success: true,
            message: "Available",
            userId: user._id
        })
    } catch (error) {
        return next(error)
    }
}

export const sendOtpToEmail = async (req, res, next) => {

    const { email } = req.body;
    // Generate token
    const otp = newOTP.generate(5, { alphabets: false, upperCase: false, specialChar: false });

    // Hash and set to resetPasswordToken
    const hashed = crypto.createHash('sha256').update(otp).digest('hex');

    // Set token expire time
    const expiryDate = Date.now() + 30 * 60 * 1000

    const message = `Hi there use the otp below to complete your registeration:\n\n${otp}\n\nif you have not 
        requested this email, then ignore it.`

    try {

        const user = await otpModel.findOne({ email: email.toLowerCase() })

        if (user) {

            // Hash and set to resetPasswordToken
            user.otp = hashed;

            // Set token expire time
            user.expiretoken = expiryDate;

            await user.save({ validateBeforeSave: false });

            return await handleEmail(user, next, message, res)

        }


        const savedUser = await otpModel.create({
            email,
            otp: hashed,
            expiretoken: expiryDate
        });

        return await handleEmail(savedUser, next, message, res)


    } catch (error) {
        return next(error)
    }
}

export const verifyOtp = async (req, res, next) => {
    const { otp } = req.body;

    try {
        // Hash URL otp
        const resetOtp = crypto.createHash('sha256').update(otp).digest('hex')

        const user = await otpModel.findOne({
            otp: resetOtp,
            expiretoken: { $gt: Date.now() }
        })

        if (!user) return next(new ErrorHandler('OTP is invalid or has expired', 200))

        return res.status(200).json({
            success: true,
            message: `OTP Verified`,
        })


    } catch (error) {
        return next(error)
    }
}

export const registerUser = async (req, res, next) => {

    try {
        const { email, password, confirmPassword } = req.body

        if (!email || !password || !confirmPassword) return next(new ErrorHandler("All fields required", 400))

        if (password !== confirmPassword) return next(new ErrorHandler("Passwords do not match", 200))

        if (password.length < 6) return next(new ErrorHandler("Password cannot be less than 6 characters", 200))

        const user = await UserModel.findOne({ email: email.toLowerCase() })

        if (user) return next(new ErrorHandler("User already registered", 200))

        //const dob = new Date(dateOfBirth)


        const savedUser = await UserModel.create({
            email: email.toLowerCase(),
            password,
            cartItems: [],
            wishItems: [],
        });



        const payload = { userid: savedUser._id }
        const authToken = await jwt.sign(payload, process.env.SECRETE, { expiresIn: '7d' })//expiresIn: '7d' before

        res.status(200).json({
            success: true,
            token: authToken,
            name: savedUser.name
        })

    } catch (error) {
        return next(error)
    }
}

//To login {{DOMAIN}}/api/login
export const loginUser = async (req, res, next) => {

    const { email, password } = req.body

    try {

        if (!email || !password) return next(new ErrorHandler("All fields required", 400))

        if (password.length < 6) return next(new ErrorHandler("Password cannot be less than 6 characters", 200))


        const user = await UserModel.findOne({ email: email.toLowerCase() }).select("+password")


        if (!user) return next(new ErrorHandler("Invalid Credentials", 200))

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return next(new ErrorHandler("Invalid Credentials", 200))
        }

        const payload = {
            userid: user._id
        }

        const authToken = await jwt.sign(payload, process.env.SECRETE, { expiresIn: '7d' })

        let name = user.name || "No name"

        res.status(200).json({
            success: true,
            token: authToken,
            name
        })

    } catch (error) {
        return next(error)
    }
}

//Forgot password {{DOMAIN}}/api/v1/password/forgot
export const forgotPassword = async (req, res, next) => {

    const { email } = req.body;

    try {

        const user = await UserModel.findOne({ email: email.toLowerCase() })

        if (!user) return next(new ErrorHandler("User with this email not found", 200))

        // Generate token
        const resetToken = crypto.randomBytes(20).toString('hex');

        // Hash and set to resetPasswordToken
        user.resettoken = crypto.createHash('sha256').update(resetToken).digest('hex');

        // Set token expire time
        user.expiretoken = Date.now() + 30 * 60 * 1000

        await user.save({ validateBeforeSave: false });


        const resetUrl = `https://www.treasurebox.ng/auth/reset/${resetToken}`;
        const message = `
            <p>Please click on the link below to reset your password:</p>
            <a href="${resetUrl}">Reset Link</a>
            <p>If you did not request this email, please ignore it.</p>
        `;

        try {
            await sendEmail({
                email: user.email,
                subject: "Treasurebox Recovery",
                message,
                html: message
            })

            return res.status(200).json({
                success: true,
                message: `Email sent to ${user.email}`
            })
        } catch (error) {
            user.resetPasswordToken = undefined;
            user.resetPasswordExpire = undefined;

            await user.save({ validateBeforeSave: false })
            return next(new ErrorHandler(error.message, 500))

        }


    } catch (error) {
        return next(error)
    }
}

//reset password {{DOMAIN}}/api/v1/verify/password/:token
export const verifyToken = async (req, res, next) => {
    const { token } = req.body;

    try {
        // Hash URL token
        const resettoken = crypto.createHash('sha256').update(token).digest('hex')

        const user = await UserModel.findOne({
            resettoken,
            expiretoken: { $gt: Date.now() }
        })

        if (!user) return next(new ErrorHandler('Password reset token is invalid or has been expired', 200))

        return res.status(200).json({
            success: true,
            message: `Token Verified`,
            userId: user._id
        })


    } catch (error) {
        return next(error)
    }
}

//reset password {{DOMAIN}}/api/v1/password/reset/:userId
export const resetPassword = async (req, res, next) => {
    const { userId } = req.params;
    const { password, confirmPassword } = req.body;

    try {

        const user = await UserModel.findById(userId)

        if (!user) return next(new ErrorHandler('Pass a valid user Id', 400))

        if (!password || !confirmPassword) return next(new ErrorHandler('All fields required', 400))

        if (password !== confirmPassword) {
            return next(new ErrorHandler('Password does not match', 200))
        }

        // Setup new password

        user.password = password;

        user.resettoken = undefined;
        user.expiretoken = undefined;

        await user.save();

        const payload = { userid: user._id }
        const authToken = await jwt.sign(payload, process.env.SECRETE, { expiresIn: '7d' })

        res.status(200).json({
            success: true,
            token: authToken,
            name: user.name
        })

    } catch (error) {
        return next(error)
    }
}

export const getLoggedInUser = async (req, res, next) => {
    const { _id } = req.user;

    try {
        const user = await UserModel.findById(_id)
            .populate("cartItems.product")
            .populate("wishItems.product")


        return res.status(200).json({
            success: true,
            user,

        })

    } catch (error) {
        return next(error)
    }
}