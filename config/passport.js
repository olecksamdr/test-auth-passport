const util = require('util');

const LocalStrategy = require('passport-local').Strategy;
const GoogleSrategy = require('passport-google-oauth').OAuth2Strategy;
const VKontakteStrategy = require('passport-vkontakte').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const User = require('../app/models/user');

const configAuth = require('./auth');

module.exports = function(passport) {

    // used to serialize the user for the session
    passport.serializeUser(function(user, done) {
        done(null, user.id);
    });

    // used to deserialize the user
    passport.deserializeUser(function(id, done) {
        User.findById(id, function(err, user) {
            done(err, user);
        });
    });

    // ===========================
    // STRATEGНY
    // ===========================

    // == Local
    passport.use('local-signup', new LocalStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true
    },
    function(req, email, password, done) {

        // asynchronous
        // User.findOne wont fire unless data is sent back
        process.nextTick(function() {

        // find a user whose email is the same as the forms email
        // we are checking to see if the user trying to login already exists
        User.findOne({ 'local.email' :  email }, function(err, user) {
            if (err)
                return done(err);

            // check to see if theres already a user with that email
            if (user) {
                return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
            } else {

                // if there is no user with that email
                // create the user
                var newUser = new User();

                // set the user's local credentials
                newUser.local.email = email;
                newUser.local.password = newUser.generateHash(password);

                // save the user
                newUser.save(function(err) {
                    if (err)
                        throw err;
                    return done(null, newUser);
                    });
                }
            });
        });
    }));

    passport.use('local-login', new LocalStrategy({
        usernameField : 'email',
        passwordField : 'password',
        passReqToCallback : true 
    },
    function(req, email, password, done) { 
        User.findOne({ 'local.email': email }, function(err, user) {
            if (err)
                return done(err);

            // if no user is found, return the message
            if (!user)
                return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash

            // if the user is found but the password is wrong
            if (!user.validPassword(password))
                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.')); // create the loginMessage and save it to session as flashdata

            // all is well, return successful user
            return done(null, user);
        });

    }));

    // == google
    passport.use('google-login', new GoogleSrategy({
            clientID: configAuth.googleAuth.clientID,
            clientSecret: configAuth.googleAuth.clientSecret,
            callbackURL: configAuth.googleAuth.callbackURL,
        },
        function (token, refreshToken, profile, done) {
            User.findOne({ 'google.id': profile.id }, function (err, user) {

                if (err) return done(err);

                if (user) return done(null, user);
                else {
                    var newUser = new User;

                    newUser.google.id = profile.id;
                    newUser.google.token = token;
                    newUser.google.name = profile.displayName;
                    newUser.google.email = profile.emails[0].value;

                    newUser.save( function (err) { 
                        if (err)
                            throw err;
                        else
                            done(null, newUser);
                    });

                }
            });
        })
    );

    // == vk
    passport.use('vk-login', new VKontakteStrategy({
        clientID:     configAuth.vkAuth.clientID,
        clientSecret: configAuth.vkAuth.clientSecret,
        callbackURL:  configAuth.vkAuth.callbackURL,
        scope: ['profile', 'email'],
        profileFields: ['email']
      },
      function (token, refreshToken, params, profile, done) {
            User.findOne({ 'vk.id': profile.id }, function (err, user) {

                if (err) return done(err);

                if (user) return done(null, user);
                else {
                    var newUser = new User;

                    newUser.vk.id = profile.id;
                    newUser.vk.token = token;
                    newUser.vk.name = profile.displayName;
                    newUser.vk.email = params.email;

                    newUser.save( function (err) { 
                        if (err)
                            throw err;
                        else
                            done(null, newUser);
                    });
                }
            });
        }
    ));

    // == facebook
    passport.use('facebook-login', new FacebookStrategy({
        clientID:     configAuth.facebookAuth.clientID,
        clientSecret: configAuth.facebookAuth.clientSecret,
        callbackURL:  configAuth.facebookAuth.callbackURL,
        profileFields: ['email', 'displayName', 'id']
    },
    function (token, refreshToken, params,  profile, done) {
            User.findOne({ 'facebook.id': profile.id }, function (err, user) {

                console.log(util.inspect(profile));
                console.log();
                console.log(util.inspect(params));

                if (err) return done(err);

                if (user) return done(null, user);
                else {
                    var newUser = new User;

                    newUser.facebook.id = profile.id;
                    newUser.facebook.token = token;
                    newUser.facebook.name = profile.displayName;
                    newUser.facebook.email = profile.emails[0].value;

                    newUser.save( function (err) { 
                        if (err)
                            throw err;
                        else
                            done(null, newUser);
                    });
                }
            });
    }));
};
