require('dotenv').config();
const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const session = require("express-session");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();
const port = 3000;


app.use(express.urlencoded({extended:true}));
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(session({
    secret:"This is a Secret Message",
    resave: false,
    saveUninitialized: true,
    cookie: {}
}));
app.use(passport.initialize());
app.use(passport.session());
mongoose.set('strictQuery', true);

mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    secrets: Array
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());
passport.serializeUser((user, done)=>{
	done(null, user.id);
});
passport.deserializeUser((id, done)=>{
	User.findById(id, (err, user)=>{
		done(err, user);
	});
});
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },(accessToken, refreshToken, profile, cb)=>{
        User.findOrCreate({googleId: profile.id}, (err, user)=>{
            return cb(err, user);
            })
        }));

app.get('/', (req, res)=>{
    res.render("home");
});
app.get('/auth/google', passport.authenticate("google", {
    scope: ["profile"]
}));
app.get('/auth/google/secrets', passport.authenticate("google", {failureRedirect: '/login'}), (req, res)=>{
    res.redirect('/secrets');
});

app.route('/login')
    .get((req, res)=>{
        if (req.isAuthenticated()){
            res.redirect("/secrets");
        } else {
            res.render("login");
        }
    })
    .post(passport.authenticate("local"), function(req, res){
        res.redirect("/secrets");
    });
app.route('/register')
    .get((req, res)=>{
        if (req.isAuthenticated()){
            res.redirect("/secrets");
        } else {
            res.render("register");
        }
    })
    .post((req, res)=>{
        User.register({username: req.body.username}, req.body.password, (err, user)=>{
            if(err){
                console.log(err);
                res.redirect('/register');
            } else {
                // only Triggered if Authentication was Successful!
                passport.authenticate("local")(req, res, ()=>{
                    res.redirect("/secrets");
                });

        }});
    });
app.route("/secrets")
    .get((req, res)=>{
        if (req.isAuthenticated()){
            User.findById(req.user.id, (err, foundUser)=>{
                const secrets = foundUser.secrets;
                res.render("secrets", {secrets: secrets});
            });
        } else {
            console.log("Not Authenticated");
            res.redirect("/login");
        }
    })
app.post('/logout', (req, res)=>{
    req.logout(err=>{
        if(err){
            res.send(err);
        }else {
            res.redirect("/");
        }
    });
});
app.route("/submit")
    .get((req, res)=>{
        if (req.isAuthenticated()){
            res.render("submit");
        } else {
            console.log("Not Authenticated");
            res.redirect("/login");
        }
    })
    .post((req, res)=>{
        User.findById(req.user.id, (err, foundUser)=>{
            if (err){
                res.send(err);
            } else {
                foundUser.secrets.push(req.body.secret);
                foundUser.save(()=>{
                    res.redirect("/secrets");
                })
            }
        })
    })
app.listen(port, ()=>{
    console.log("Server running on port 3000");
})

