// authController.js
require("dotenv").config();
const nodemailer = require("nodemailer");
const bcrypt = require("bcrypt");
const crypto = require("crypto")
const jwt = require ("jsonwebtoken")
const UserModel = require('../models/userModel');
const sellers = require('../models/sellersmodel');
const Admins = require('../models/Adminsmodel');
const TokenModel = require('../models/tokenModel');

async function register(req, res, next) {
    try {
        const { name, email, password } = req.body;

        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user with the hashed password
        const user = await UserModel.create({
            name,
            email,
            password: hashedPassword,
        });

        res.status(200).json({
            message: 'Registration was successful',
            user: {
                name: user.name,
                email: user.email,
                password:user.password,
            },
        });
    } catch (err) {
        let msg = err;
        if (err.code === 11000) {
            msg = 'Email has been used by another user, please change your email address';
        }

        res.status(500).json({
            message: 'Registration was not successful',
            error: msg,
        });
    }
}



const registerAsAdmin = async (req, res, next) => {
    try {
        let email = req.body.email;
        let password = req.body.password;
        let name = req.body.name
        let company = req.body.company

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const AdminsData = {
            email,
            password: hashedPassword, // Save the hashed password
            name,
            company,
        };

        const addedAdmins = await Admins.create(AdminsData);
        res.status(200).json({ message: "Admin Successfully Added", addedAdmins });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error registering admin', error });
    }
};

const registerseller = async (req, res, next) => {
    try {
        let email = req.body.email;
        let password = req.body.password;
        let company = req.body.company;
        let location = req.body.location;
        let name = req.body.name;

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        const sellersData = {
            email,
            password: hashedPassword, // Save the hashed password
            company,
            location,
            name,
        };

        const addedsellers = await sellers.create(sellersData);
        res.status(200).json({ message: "Seller Successfully Added", addedsellers });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error registering seller', error });
    }
};


const loginAsAdmin = async (req, res, next) => {
    try {
        let email = req.body.email;
        let password = req.body.password;

        const findAdmin = await Admins.findOne({ email });

        if (!findAdmin) {
            res.status(400).json({ message: "You are not an Admin" });
        } else {
            // Compare the provided password with the hashed password in the database
            const passwordMatch = await bcrypt.compare(password, findAdmin.password);

            if (passwordMatch) {
                const token = jwt.sign(
                    { id: findAdmin.id, email: findAdmin.email },
                    process.env.JWT_SECRET,
                    { expiresIn: "1h" }
                  );
                res.status(200).json({
                    message: "Welcome Back Here Is Your Token: ",token,
                });
            } else {
                res.status(400).json({ message: "Incorrect password" });
            }
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Cant login as Admin " });
    }
};



/*
  const token = jwt.sign(
          { id: foundUser.id, email: foundUser.email },
          process.env.JWT_SECRET,
          { expiresIn: "1h" }
        );
        
*/
////
const login = async (req, res, next) => {
    try {
        let email = req.body.email;
        let password = req.body.password;

        const user = await UserModel.findOne({ email });

        if (user) {
            // Compare the provided password with the hashed password in the database
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                res.status(200).json({
                    message: "LogIn Successful",
                    user: {
                        name: user.name,
                        email: user.email,
                        password: user.password,
                    },
                });
            } else {
                res.status(401).json({ message: "Incorrect password" });
            }
        } else {
            res.status(404).json({ message: "User not found. Please register." });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unknown error occurred" });
    }
};



async function changePassword(req, res, next) {
    try {
        const email = req.body.email;
        const oldPassword = req.body.oldPassword;
        const newPassword = req.body.newPassword;

        // Fetch the user from the database
        const user = await UserModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                message: "User not found",
            });
        }

        // Compare the old password with the hashed password from the database
        const isOldPasswordCorrect = await bcrypt.compare(oldPassword, user.password);

        if (!isOldPasswordCorrect) {
            return res.status(401).json({
                message: "Incorrect old password",
            });
        }

        // Hash the new password
        const hashedNewPassword = await bcrypt.hash(newPassword, 10);

        // Update the password in the database
        const updateResult = await UserModel.updateOne({ email }, { password: hashedNewPassword });

        if (updateResult.nModified === 0) {
            return res.status(200).json({
                message: "Update was successful, but no modification was made. Please enter a different password.",
            });
        } else {
            return res.status(200).json({
                message: "Password change was successful",
            });
        }
    } catch (err) {
        console.error("Error during password change:", err);
        return res.status(500).json({
            message: "Unknown error occurred",
            error: err,
        });
    }
}

async function forgotPassword(req, res, next) {
    function generateSixDigitToken() {
        const min = 100000; 
        const max = 999999; 
        return Math.floor(Math.random() * (max - min + 1)) + min;
    }

    try {
        const userEmail = req.body.email;
        const token = generateSixDigitToken();
        const expirationTime = new Date(Date.now() + 2 * 60 * 1000); // 2 min

        const user = await UserModel.findOne({ email: userEmail });

        if (!user) {
            return res.status(404).json({ message: "No user found with this email address" });
        }

        let transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.USER, 
                pass: process.env.PASS,
            },
        });

        const mail = {
            from: process.env.USER,
            to: userEmail,
            subject: "Password Reset Request",
            text: `(${token}) You have requested a password reset. Click the link to reset: http://localhost:2000/change-forgotpassword?token=${token}`,
        };

        await transporter.sendMail(mail);

        await TokenModel.create({ token, userId: user._id, email: userEmail, expirationTime });

        res.status(200).json({ message: "Password reset email sent successfully" });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Unknown error occurred", error: error.message });
    }
}


async function changeforgetpass(req, res, next) {
    try {
        const userEmail = req.body.email;
        const newPassword = req.body.password;
        const token = req.body.token;

        const tokenData = await TokenModel.findOne({ email: userEmail, token: token });

        if (!tokenData) {
            return res.status(404).json({ message: "Incorrect Token" });
        }

        const now = new Date();
        if (now > new Date(tokenData.expirationTime)) {
            return res.status(401).json({ message: "Token has expired" });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        const updateResponse = await UserModel.updateOne({ email: userEmail }, { password: hashedPassword });

        if (updateResponse.modifiedCount > 0) {
            res.status(200).json({ message: "Password reset successfully" });
        } else {
            res.status(400).json({ message: "Password reset was not successful" });
        }

        await TokenModel.deleteOne({ _id: tokenData._id });

    } catch (error) {
        console.error(error);
        return res.status(500).json({ message: "Unknown error occurred", error: error.message });
    }
}


function findbyid(req, res, next) {
    const id = req.params.id;

    UserModel.findById(id)
        .then((user) => {
            if (!user) {
                res.status(404).json({ message: "User not found" });
            } else {
                res.status(200).json({ user });
            }
        })
        .catch((err) => {
            res.status(500).json({ message: "Unknown error occurred", err });
        });
}

function updateuserinfo(req, res, next) {
        let name = req.body.name;
        let newData = {};

        if (req.body.hasOwnProperty("email")) {
            newData.email = req.body.email;
        }

        if (req.body.hasOwnProperty("password")) {
            newData.password = req.body.password;
        }

        UserModel.updateOne({ name }, newData)
            .then((done) => {
                let message = "Update was successful";
                if (done.hasOwnProperty("modifiedCount") && done.modifiedCount == 0) {
                    message = "Update was successful, but no modification was made. Please enter different data from the existing ones";
                }
                res.status(200).json({
                    message,
                    done,
                });
            })
            .catch((err) => {
                res.status(500).json({
                    message: "Unknown error occurred",
                });
            });
    };


function deleteuser(req,res,next){
    let { email, name, password } = req.body;

    UserModel.deleteOne({ email })
        .then((done) => {
            res.status(200).json({
                message: "Deletion was successful",
                done,
            });
        })
        .catch((err) => {
            res.status(500).json({
                message: "Deletion failed",
            });
        });
};



module.exports = {
    register,
    login,
    changePassword,
    forgotPassword,
    changeforgetpass,
    findbyid,
    updateuserinfo,
    deleteuser,
    registerAsAdmin,
    registerseller,
    loginAsAdmin,
};
