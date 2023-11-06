const User = require("../models/User");
const bcrypt = require("bcrypt");
const LocalStrategy = require("passport-local").Strategy;
const JwtStrategry = require("passport-jwt").Strategy;
const { fromAuthHeaderAsBearerToken } = require("passport-jwt").ExtractJwt;
require("dotenv").config();
const localStrategy = new LocalStrategy(async (username, password, done) => {
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

const jwtStrategry = new JwtStrategry(
  {
    jwtFromRequest: fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET_KEY,
  },
  async (payload, done) => {
    try {
      if (Date.now() / 1000 > payload.exp) {
        return done({ message: "Token is expiered" });
      }

      const user = await User.findById(payload._id);
      if (!user) return done({ message: "There is no user", status: 401 });
      return done(null, user);
    } catch (error) {
      done(error);
    }
  }
);

module.exports = { localStrategy, jwtStrategry };
