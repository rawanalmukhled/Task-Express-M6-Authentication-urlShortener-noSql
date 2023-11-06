const User = require("../../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const localStrategy = require("../../middlewares/passport");
require("dotenv").config();

const generateToken = (user, next) => {
  try {
    const payload = {
      _id: user._id,
      username: user.username,
    };
    return jwt.sign(payload, process.env.JWT_SECRET_KEY, { expiresIn: "1h" });
  } catch (error) {
    next(error);
  }
};

exports.signup = async (req, res, next) => {
  try {
    const saltRounds = 10;

    const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);
    req.body.password = hashedPassword;
    const newUser = await User.create(req.body);
    // res.status(201).json("Successfully signed up!");

    const token = generateToken(newUser);

    res.status(200).json({ token });
  } catch (err) {
    next(err);
  }
};

exports.signin = async (req, res) => {
  try {
    const token = generateToken(req.user);
    res.status(201).json({ token });
  } catch (err) {
    res.status(500).json("Server Error");
  }
};

exports.getUsers = async (req, res) => {
  try {
    const users = await User.find().populate("urls");
    res.status(201).json(users);
  } catch (err) {
    next(err);
  }
};
