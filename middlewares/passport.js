const User = require("../models/User");
const bcrypt = require("bcrypt");

const LocalStorage = require("passport-local").Strategy;
const localStrategy = new LocalStorage(async (username, password, done) => {
  try {
    const user = await User.findOne({
      username: username,
    });

    if (!user) return done({ message: "User or password is wrong" });

    const pass = await bcrypt.compare(password, user.password);

    if (!pass) return done({ message: "User or password is wrong" });
    return done(null, user);
  } catch (error) {
    done(error);
  }
});

module.exports = localStrategy;
