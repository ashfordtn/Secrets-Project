require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const ejs = require('ejs');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true}));

// Session configuration and passport initialization
app.use(session({
    secret: 'Our little secret.',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// DB Connection
mongoose.connect('mongodb://localhost:27017/userDB');

// User Schema and Passport plugin
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// User model
const User = new mongoose.model("User", userSchema);

// Setting up passport
passport.use(User.createStrategy());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

//Google Authentication

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  (accessToken, refreshToken, profile, cb) => {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, (err, user) => {
      return cb(err, user);
    });
  }
));

// Routes
app.get('/', (req, res) => {
    res.render('home');
});

app.get('/auth/google',
    passport.authenticate('google',{scope:['profile']})
    );
app.get('/auth/google/secrets', 
    passport.authenticate('google',{failureRedirect:'/login'}),
    (req,res) => {
        res.redirect('/secrets');
    });

app.get('/login', (req, res) => {
    res.render('login');
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.get('/secrets', (req,res) => {
    if ( req.isAuthenticated() ) {
        res.render('secrets');
    } else {
        res.redirect('/login');
    };
});

app.get('/logout', (req,res) => {
    req.logout((err)=>{
        if (!err) {
            res.redirect('/');
        };
    });
});

app.post('/register',(req,res) => {
    User.register({username: req.body.username}, req.body.password, (err,user) => {
        if ( err ) {
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res,()=>{
                res.redirect('/secrets');
            });
        };
    });
});

app.post('/login', (req,res) => {
    const user = new User({
        username: req.body.username, 
        password: req.body.password
    });
    req.login(user,(err) => {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate('local')(req,res, () => {
                res.redirect('/secrets');
            });
        };
    });
});

// Starting Server 
app.listen(3000, () => {
    console.log('Server started on port 3000');
});