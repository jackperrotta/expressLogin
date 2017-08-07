var express = require('express');
var router = express.Router();
var expressValidator = require('express-validator');
var passport = require('passport');

var bcrypt = require('bcrypt');
const saltRounds = 10;

/* GET home page. */
router.get('/', function(req, res) {
    console.log(req.user);
    console.log(req.isAuthenticated());
    res.render('home', { title: 'Home' });
});

/* GET profile Page*/
router.get('/profile', authenticationMiddleware(), function(req, res) {

        res.render('profile', { title: 'Profile' });
    });



/* GET login Page*/
router.get('/login', function(req, res) {
    res.render('login', { title: 'Login' });
});

/* POST login, still needs error message for incorrect password */

// router.post('/login', passport.authenticate(
// 	'local', {
// 		successRedirect: '/profile',
// 		failureRedirect: '/login'
// 	}));

router.post('/login', function(req, res) {

    req.checkBody('username', 'Email is required, please try again!').notEmpty();
    req.checkBody('username', 'The email you entered is invalid, please try again.').isEmail();
    req.checkBody('password', 'Password is required, please try again!').notEmpty();

    //validate 
    var errors = req.validationErrors();

    if (errors) {

        res.render('login', {
            title: 'Login',
            errors: errors
        });

    } else {
        passport.authenticate('local', {
            successRedirect: '/profile',
            failureRedirect: '/login'

        })(req, res);
    }
});

/* Logout and destory cookie*/
router.get('/logout', function(req, res) {
    req.logout();
    req.session.destroy();
    res.redirect('/');
});

/* GET registration page*/

router.get('/register', function(req, res, next) {
    res.render('register', { title: 'Registration' });
});

/* POST registration, validate form and push to db */

router.post('/register', function(req, res, next) {
    req.checkBody('email', 'Email cannot be empty.').notEmpty();
    // req.checkBody('username', 'Username field cannot be empty.').notEmpty();
    // req.checkBody('username', 'Username must be between 4-15 characters long.').len(4, 15);
    req.checkBody('email', 'The email you entered is invalid, please try again.').isEmail();
    req.checkBody('email', 'Email address must be between 4-100 characters long, please try again.').len(4, 100);
    req.checkBody('password', 'Password must be 8 characters long.').len(8, 100);
    // req.checkBody("password", "Password must include one lowercase character, one uppercase character, a number, and a special character.").matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?!.* )(?=.*[^a-zA-Z0-9]).{8,}$/, "i");
    // req.checkBody('password2', 'Password must be between 8-100 characters long.').len(8, 100);
    req.checkBody('password2', 'Passwords do not match, please try again.').equals(req.body.password);

    // Additional validation to ensure username is alphanumeric with underscores and dashes
    // req.checkBody('username', 'Username can only contain letters, numbers, or underscores.').matches(/^[A-Za-z0-9_-]+$/, 'i');

    const errors = req.validationErrors();

    if (errors) {
        console.log(`errors: ${JSON.stringify(errors)}`);

        res.render('register', {
            title: 'Registration Error',
            errors: errors
        });
    } else {

        const email = req.body.email;
        const password = req.body.password;

        const db = require('../db.js');

        bcrypt.hash(password, saltRounds, function(err, hash) {
            // Store hash in your password DB.
            db.query('INSERT INTO customers (email, password) VALUES (?, ?)', [email, hash],
                function(error, results, fields) {
                    if (error) throw error;

                    db.query('SELECT LAST_INSERT_ID() as user_id', function(error, results, fields) {
                        if (error) throw error;

                        const user_id = results[0];

                        console.log(results[0]);
                        req.login(user_id, function(err) {
                            res.redirect('/');
                        });
                    });

                })
        });
    }
});

passport.serializeUser(function(user_id, done) {
    done(null, user_id);
});

passport.deserializeUser(function(user_id, done) {
    done(null, user_id);
});


function authenticationMiddleware() {
    return (req, res, next) => {
        console.log(`req.session.passport.user: ${JSON.stringify(req.session.passport)}`);

        if (req.isAuthenticated()) return next();
        res.redirect('/login')
    }
}

module.exports = router;