const express = require("express");
const router = express.Router();

const User = require("../models/User");
const argon2 = require("argon2");
const verifyToken = require("../middleware/auth");

const jwt = require("jsonwebtoken");

// @route GET  api/auth
// @desc Check if user logged in
// @access Public

router.get("/", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user)
      return res
        .status(400)
        .json({ success: false, message: "User not found" });
    res.json({ success: true, user });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

// Router POSt api/auth/register
//@desc Register user
// @access Public

router.post("/register", async (req, res) => {
  const { username, password } = req.body;

  //simple validation

  if (!username || !password)
    return res
      .status(400)
      .json({ success: false, message: "Missing username and/or password" });

  try {
    //Check for existing user
    const user = await User.findOne({ username });
    if (user)
      return res
        .status(400)
        .json({ success: false, message: "Username already taken " });

    const hashPassword = await argon2.hash(password);
    const newUser = new User({ username, password: hashPassword });
    await newUser.save();

    //return token
    const accessToken = jwt.sign(
      { userId: newUser._id },
      `${process.env.ACCESS_TOKEN_SERECT}`
    );
    res.json({
      success: true,
      message: "User created successfully",
      accessToken,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

//Route POST api/auth/login
//desc Login user
//procces public

router.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password)
    return res
      .status(400)
      .json({ success: false, message: "Missing username and/or password" });
  try {
    // check for existing user

    const user = await User.findOne({ username });
    if (!user)
      return res
        .status(400)
        .json({ success: false, message: "Incorrect username or password" });
    //username found
    const passwordValid = await argon2.verify(user.password, password);
    if (!passwordValid)
      return res
        .status(400)
        .json({ success: false, message: "Incorrect username or password" });

    //All good
    const accessToken = jwt.sign(
      { userId: user._id },
      `${process.env.ACCESS_TOKEN_SERECT}`
    );
    res.json({
      success: true,
      message: "User logged in  successfully",
      accessToken,
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

module.exports = router;
