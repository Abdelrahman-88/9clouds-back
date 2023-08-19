const { OAuth2Client } = require('google-auth-library');
const { StatusCodes } = require('http-status-codes');
const jwt = require('jsonwebtoken');
const { nanoid } = require("nanoid")
const User = require('../model/user.model');
const client = new OAuth2Client(process.env.GOOGLEClientID)

exports.googleLogin = async(req, res) => {
    try {
        const { name, idToken } = req.body
        client.verifyIdToken({ idToken, audience: process.env.GOOGLEClientID }).then(async(result) => {
            let { email_verified, email } = result.payload
            email = email.toLowerCase()
            if (email_verified) {
                const user = await User.findOne({ email, deactivated: false })
                if (user) {
                    const data = await User.findByIdAndUpdate({ _id: user.id }, { logedIn: true });
                    const { password, ...rest } = user._doc
                    const token = jwt.sign({...rest }, process.env.SECRET_KEY)
                    res.status(StatusCodes.OK).json({ message: "done", token });
                } else {
                    const verificationKey = nanoid();
                    const newUser = new User({ name, email, password: nanoid(), verified: true, logedIn: true, verificationKey, companyName: "NA", position: "NA" });
                    const data = await newUser.save();
                    const { password, ...rest } = data._doc
                    const token = jwt.sign({...rest }, process.env.SECRET_KEY, {
                        expiresIn: process.env.TOKEN_EXPIRATION
                    });

                    res.json({ message: "done", token });
                }
            } else {
                res.status(StatusCodes.BAD_REQUEST).json({ message: "Invalid google account" })
            }
        }).catch((error => {
            res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: "Failed to login" });
        }))
    } catch (error) {
        res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({ message: "Failed to login" });
    }
}