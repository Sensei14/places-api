const HttpError = require("../models/http-error");
const { validationResult } = require("express-validator");
const User = require("../models/user");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const getUsers = async (req, res, next) => {
  let users;
  try {
    users = await User.find({}, "-password");
  } catch (error) {
    return next(new HttpError("Could not get any users", 500));
  }

  res.json({ users: users.map(user => user.toObject({ getters: true })) });
};

const signup = async (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return next(new HttpError("Invalid inputs passed. Check your data", 422));
  }

  const { name, email, password } = req.body;

  let existingUser;
  try {
    existingUser = await User.findOne({ email });
  } catch (error) {
    return next(new HttpError("Signing up failed.", 500));
  }

  if (existingUser) {
    return next(new HttpError("User exist already.", 422));
  }

  let hashedPassword;
  try {
    hashedPassword = await bcrypt.hash(password, 12);
  } catch (err) {
    return next(new HttpError("Could not create user.", 500));
  }

  const createdUser = new User({
    name,
    email,
    password: hashedPassword,
    image: req.file.path,
    places: []
  });

  try {
    await createdUser.save();
  } catch (error) {
    return next(new HttpError("Signing up failed.", 500));
  }

  let token;
  try {
    token = jwt.sign(
      { userId: createdUser.id, email: createdUser.email },
      "secret_token_key",
      { expiresIn: "1h" }
    );
  } catch (error) {
    return next(new HttpError("Signing up failed.", 500));
  }

  res
    .status(201)
    .json({ userId: createdUser.id, email: createdUser.email, token });
};

const login = async (req, res, next) => {
  const { email, password } = req.body;

  let existingUser;
  try {
    existingUser = await User.findOne({ email });
  } catch (error) {
    return next(new HttpError("Logging  failed.", 500));
  }
  if (!existingUser) {
    return next(new HttpError("Invalid credentials.", 401));
  }

  let isValidPassword = false;
  try {
    isValidPassword = await bcrypt.compare(password, existingUser.password);
  } catch (error) {
    return next(new HttpError("Invalid credentials. Try again", 500));
  }

  if (!isValidPassword) {
    return next(new HttpError("Invalid credentials.", 403));
  }

  let token;
  try {
    token = jwt.sign(
      { userId: existingUser.id, email: existingUser.email },
      "secret_token_key",
      { expiresIn: "1h" }
    );
  } catch (error) {
    return next(new HttpError("Logging in failed.", 500));
  }

  res.json({
    userId: existingUser.id,
    email: existingUser.email,
    token
  });
};

exports.getUsers = getUsers;
exports.login = login;
exports.signup = signup;
