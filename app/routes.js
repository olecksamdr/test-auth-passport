var path = require('path');

module.exports = function(app, passport) {
    app.get('/', function(req, res) {
        res.sendFile(path.resolve(__dirname, '..', 'views', 'login.html')); // load the index.ejs file
    });

    app.get('/login', function(req, res) {

        // render the page and pass in any flash data if it exists
        res.render('login2.ejs', { message: req.flash('loginMessage') }); 
    });

    // ===========================================
    // ROUTES FOR DIFFERENT AUTHORIZATION METHODS
    // ===========================================

    // == LOCAL

    app.post('/login', passport.authenticate('local-login', {
        successRedirect : '/profile',
        failureRedirect : '/login',
        failureFlash : true // allow flash messages
    }));

    app.get('/signup', function(req, res) {
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });

    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect : '/profile',
        failureRedirect : '/signup', 
        failureFlash : true // allow flash messages
    }));

    // == GOOGLE

    app.get('/auth/google', passport.authenticate('google-login', { scope: ['profile', 'email'] }));

    app.get('/auth/google/callback',
            passport.authenticate('google-login', {
                    successRedirect : '/profile',
                    failureRedirect : '/'
            }));

    // == VK

    app.get('/auth/vk', passport.authenticate('vk-login', { scope : ['profile', 'email']}));

    app.get('/auth/vk/callback',
            passport.authenticate('vk-login', {
                    successRedirect : '/profile',
                    failureRedirect : '/'
            }));

    // == FACEBOOK

    app.get('/auth/facebook', passport.authenticate('facebook-login', { scope: ['email'] } ));

    app.get('/auth/facebook/callback',
            passport.authenticate('facebook-login', {
                    successRedirect : '/profile',
                    failureRedirect : '/'
            }));


    // ===========================================

    app.get('/profile', isLoggedIn, function(req, res) {
        console.log(req.user);
        res.render('profile.ejs', {
            user : req.user // get the user out of session and pass to template
        });
    });

    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });
};

// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {

    // if user is authenticated in the session, carry on 
    if (req.isAuthenticated())
        return next();

    // if they aren't redirect them to the home page
    res.redirect('/');
}