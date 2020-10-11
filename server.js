//jshint esversion:6
require("dotenv").config();
const express = require("express");
const app = express();
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const passport = require("passport");
const session = require("express-session");
const passportLocalMongoose = require("passport-local-mongoose");
const googleStrategy = require("passport-google-oauth20").Strategy;
const findorcreate = require("mongoose-findorcreate");

app.use(session({
  secret: process.env.SECRET_KEY,
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

app.use(bodyParser.urlencoded({
  extended: true
}));
app.set("view engine", "ejs");
app.use(express.static("public"));

mongoose.connect("mongodb://localhost:27017/Secrets", {
  useNewUrlParser: true,
  useUnifiedTopology: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findorcreate);

const userModel = mongoose.model("userCollection", userSchema);

passport.use(userModel.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  userModel.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new googleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    userModel.findOrCreate({
      googleId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/auth/google", passport.authenticate("google", {
  scope: ["profile"]
}));

app.get("/auth/google/secrets", passport.authenticate("google", {
  failureRedirect: "/login"
}), function(req, res) {
  console.log(req);
  res.redirect("/secrets");
});
app.get("/secrets", function(req, res) {
  userModel.find({
    secret: {
      $ne: null
    }
  }, function(err, found) {
    res.render("secrets", {
      usersecrets: found
    });
  });
});

app.get("/logout", function(req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("login");
  }
});

app.post("/register", function(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  userModel.register({
    username: username
  }, password, function(err, user) {
    if (err) {
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, function() { // try by using func(req,res)
        res.redirect("/secrets");
      });
    }
  });

});

app.post("/login", function(req, res) {
  const username = req.body.username;
  const password = req.body.password;
  const user = new userModel({
    username: username,
    password: password
  });
  req.login(user, function(err) {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local")(req, res, function() {
        res.redirect("/secrets");
      });
    }
  });
});

app.post("/submit", function(req, res) {
const newsecret = new userModel({
  secret: req.body.secret
});
newsecret.save();
res.redirect("/secrets");
});

app.listen(3000, function() {
  console.log("Started the server at port 3000");
});
