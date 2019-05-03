//jshint esversion:6
// BASE SETUP
// =============================================================================
const dotenv = require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const port = process.env.PORT || 3000; // set our port

const app = express();//define our app usig express


app.set('view engine', 'ejs');

// configure app to use bodyParser()
// this will let us get the data from a POST
app.use(bodyParser.urlencoded({extended: true}));

app.use(express.static("public"));

app.use(session({
  secret: process.env.SECRET,//Any string you'd like
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


//the following line is in case we want to work with localhost
//mongoose.connect(localhost:27017/userDB, {useNewUrlParser: true});

// connect to our database to MongoAtlas
mongoose.connect(process.env.MONGOLAB_URI, {useNewUrlParser: true});
mongoose.set("useCreateIndex", true);

//define our model
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

// CHANGE: USE "createStrategy" INSTEAD OF "authenticate"
passport.use(User.createStrategy());


passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});



passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


passport.use(new FacebookStrategy({
  clientID: process.env.FACEBOOK_APP_ID,
  clientSecret: process.env.FACEBOOK_APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// on routes /auth/google
// ----------------------------------------------------

  app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });



  // Redirect the user to Facebook for authentication.  When complete,
  // Facebook will redirect the user back to the application at
  //     /auth/facebook/callback
  app.get('/auth/facebook',
    passport.authenticate('facebook'));

  app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

  // routes of the app
  // =============================================================================

  app.get("/", (req, res)=>{
    res.render("home");
  });



  // on routes that end in /login
  // ----------------------------------------------------
  app.route("/login")

    // accessed at GET http://localhost:3000/login
    .get((req, res)=>{res.render("login");})

    // accessed at POST http://localhost:3000/login
    .post((req, res)=>{
    const user = new User({
      email: req.body.username,
      password: req.body.password
    });

    req.login(user, (err) =>{
      if(err)
        res.redirect("/login");

      passport.authenticate("local")(req, res, ()=>{
      res.redirect("/secrets");
        });
    });
  });


  // on routes that end in /register
  // ----------------------------------------------------

  app.route("/register")

    // accessed at GET http://localhost:3000/register
    .get((req, res)=>{res.render("register");})

    // accessed at POST http://localhost:3000/register

    .post((req, res)=>{
        User.register({username: req.body.username}, req.body.password, (err, user) =>{
          if(err)
            res.redirect("/login");

          if(user){
              passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
              });
          }else
              res.redirect("/login");

        });
    });


  // on routes that end in /submit
  // ----------------------------------------------------

  app.route("/submit")

    // accessed at GET http://localhost:3000/submit
    .get((req, res)=>{
        if(req.isAuthenticated())
          res.render("submit");
        else
          res.redirect("/login");
    })

    // accessed at GET http://localhost:3000/submit
    .post((req, res)=>{
        //find all elements of the items collection and the callback returns and array of matched elements
        User.findById(req.user.id, (err, foundUser) => {
          if(err)
            res.send(err);

          if(foundUser){
              foundUser.secret = req.body.secret;
              foundUser.save(()=>{ res.redirect("/secrets")});
          }else
            res.send("User not found!");

        });
  });

  // accessed at GET http://localhost:3000/secrets
  app.get("/secrets", (req, res)=>{
    User.find({secret: {$ne: null}}, (err, secretsFound) =>{
      if(err)
        res.send(err);

      if(secretsFound)
          res.render("secrets", {secretsFound: secretsFound});

    });
  });

  // accessed at GET http://localhost:3000/logout
  app.get("/logout", (req, res)=>{
    req.logout();
    res.redirect("/");
  });



// START THE SERVER
// =============================================================================
app.listen(port, function() {
  console.log('Magic happens on port ' + port);
});
