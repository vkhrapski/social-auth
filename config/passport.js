// load all the things we need
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
var TwitterStrategy = require('passport-twitter').Strategy;
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
var VkontakteStrategy = require('passport-vkontakte').Strategy;
var User = require('../app/models/user');
var configAuth = require('./auth'); // use this one for testing

module.exports = function(passport) 
{

    passport.serializeUser(function(user, done) 
    {
        done(null, user.id);
    });

    passport.deserializeUser(function(id, done) 
    {
        User.findById(id, function(err, user) 
        {
            done(err, user);
        });
    });

    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
    passport.use('local-login', new LocalStrategy(
        {
            usernameField : 'email',
            passwordField : 'password',
            passReqToCallback : true
        },
        function(req, email, password, done) 
        {
            if (email) 
                email = email.toLowerCase();

            process.nextTick(
                function() 
                {
                    User.findOne(
                        { 
                            'local.email' :  email 
                        },
                        function(err, user) 
                        {   
                            if (err)
                                return done(err);
                            if (!user)
                                return done(null, false, req.flash('loginMessage', 'No user found.'));
                            if (!user.validPassword(password))
                                return done(null, false, req.flash('loginMessage', 'Oops! Wrong password.'));
                            else
                                return done(null, user);
                        }
                    );
                }
            );

        }
    )
);

    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
    passport.use('local-signup', new LocalStrategy(
        {
            // by default, local strategy uses username and password, we will override with email
            usernameField : 'email',
            passwordField : 'password',
            passReqToCallback : true // allows us to pass in the req from our route (lets us check if a user is logged in or not)
        },
        function(req, email, password, done) 
        {
            if (email)
                email = email.toLowerCase(); // Use lower-case e-mails to avoid case-sensitive e-mail matching

            // asynchronous
            process.nextTick(
                function() 
                {
                    // if the user is not already logged in:
                    if (!req.user) 
                    {
                        User.findOne(
                            {
                                'local.email' :  email
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user) 
                                {
                                    return done(null, false, req.flash('signupMessage', 'That email is already taken.'));
                                }
                                else 
                                {
                                    var newUser = new User();
                                    newUser.local.email = email;
                                    newUser.local.password = newUser.generateHash(password);
                                    newUser.save(
                                        function(err) 
                                        {
                                            if (err)
                                                return done(err);

                                            return done(null, newUser);
                                        }
                                    );
                                }
                            }
                        );
                    } 
                    else if ( !req.user.local.email ) 
                    {
                        User.findOne(
                            {
                                'local.email' :  email
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user) 
                                {
                                    return done(null, false, req.flash('loginMessage', 'That email is already taken.'));
                                } 
                                else
                                {
                                    var user = req.user;
                                    user.local.email = email;
                                    user.local.password = user.generateHash(password);
                                    user.save(
                                        function (err) 
                                        {
                                            if (err)
                                                return done(err);
                                            
                                            return done(null,user);
                                        }
                                    );
                                }
                            }
                        );
                    } 
                    else 
                    {
                        return done(null, req.user);
                    }

                }
            );

        }
    ));

    // =========================================================================
    // FACEBOOK ================================================================
    // =========================================================================
    passport.use(new FacebookStrategy(
        {
            clientID        : configAuth.facebookAuth.clientID,
            clientSecret    : configAuth.facebookAuth.clientSecret,
            callbackURL     : configAuth.facebookAuth.callbackURL,
            passReqToCallback : true
        },
        function(req, token, refreshToken, profile, done) 
        {
            process.nextTick(
                function() 
                {
                    if (!req.user) 
                    {
                        User.findOne(
                            { 
                                'facebook.id' : profile.id 
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user) 
                                {
                                    if (!user.facebook.token) 
                                    {
                                        user.facebook.token = token;
                                        user.facebook.name  = profile.name.givenName + ' ' + profile.name.familyName;
                                        user.facebook.email = (profile.emails[0].value || '').toLowerCase();

                                        user.save(
                                            function(err) 
                                            {
                                                if (err)
                                                    return done(err);
                                                return done(null, user);
                                            }
                                        );
                                    }
                                    return done(null, user); // user found, return that user
                                } 
                                else
                                {
                                    var newUser = new User();
                                    newUser.facebook.id = profile.id;
                                    newUser.facebook.token = token;
                                    newUser.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                                    newUser.facebook.email = (profile.emails[0].value || '').toLowerCase();

                                    newUser.save(
                                        function(err) 
                                        {
                                            if (err)
                                                return done(err);
                                                
                                            return done(null, newUser);
                                        }
                                    );
                                }
                            }
                        );

                    } 
                    else
                    {
                        var user = req.user;
                        user.facebook.id = profile.id;
                        user.facebook.token = token;
                        user.facebook.name = profile.name.givenName + ' ' + profile.name.familyName;
                        user.facebook.email = (profile.emails[0].value || '').toLowerCase();

                        user.save(
                            function(err) 
                            {
                                if (err)
                                    return done(err);
                                    
                                return done(null, user);
                            }
                        );

                    }
                }
            );

        }
    ));

    // =========================================================================
    // TWITTER =================================================================
    // =========================================================================
    passport.use(new TwitterStrategy(
        {
            consumerKey : configAuth.twitterAuth.consumerKey,
            consumerSecret : configAuth.twitterAuth.consumerSecret,
            callbackURL : configAuth.twitterAuth.callbackURL,
            passReqToCallback : true
        },
        function(req, token, tokenSecret, profile, done) 
        {

            process.nextTick(
                function() 
                {
                    if (!req.user) 
                    {
                        User.findOne(
                            {
                                'twitter.id' : profile.id
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user) 
                                {
                                    if (!user.twitter.token) 
                                    {
                                        user.twitter.token       = token;
                                        user.twitter.username    = profile.username;
                                        user.twitter.displayName = profile.displayName;
                                        user.save(
                                            function(err) 
                                            {
                                                if (err)
                                                    return done(err);
                                                return done(null, user);
                                            }
                                        );
                                    }
                                    return done(null, user);
                                }
                                else 
                                {
                                    var newUser = new User();
                                    newUser.twitter.id = profile.id;
                                    newUser.twitter.token = token;
                                    newUser.twitter.username = profile.username;
                                    newUser.twitter.displayName = profile.displayName;

                                    newUser.save(
                                        function(err) 
                                        {
                                            if (err)
                                                return done(err);
                                            return done(null, newUser);
                                        }
                                    );
                                }
                            }
                        );

                    }
                    else
                    {
                        var user = req.user;
                        user.twitter.id = profile.id;
                        user.twitter.token = token;
                        user.twitter.username = profile.username;
                        user.twitter.displayName = profile.displayName;

                        user.save(
                            function(err) 
                            {
                                if (err)
                                    return done(err);
                                return done(null, user);
                            }
                        );
                    }
                }
            );

        }
    ));
// =========================================================================
// =========================================================================
    passport.use(new GoogleStrategy(
        {
            clientID : configAuth.googleAuth.clientID,
            clientSecret : configAuth.googleAuth.clientSecret,
            callbackURL : configAuth.googleAuth.callbackURL,
            passReqToCallback : true
        },
        function(req, token, refreshToken, profile, done) 
        {
            process.nextTick(
                function() 
                {
                    if (!req.user) 
                    {
                        User.findOne(
                            {
                                'google.id' : profile.id 
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user)
                                {
                                    if (!user.google.token) 
                                    {
                                        user.google.token = token;
                                        user.google.name  = profile.displayName;
                                        user.google.email = (profile.emails[0].value || '').toLowerCase();
                                        user.save(
                                            function(err) 
                                            {
                                                if (err)
                                                    return done(err);
                                                    
                                                return done(null, user);
                                            }
                                        );
                                    }
                                    return done(null, user);
                                } 
                                else
                                {
                                    var newUser = new User();
                                    newUser.google.id = profile.id;
                                    newUser.google.token = token;
                                    newUser.google.name = profile.displayName;
                                    newUser.google.email = (profile.emails[0].value || '').toLowerCase();
                                    
                                    newUser.save(
                                        function(err)
                                        {
                                            if (err)
                                                return done(err);
                                            return done(null, newUser);
                                        }
                                    );
                                }
                            }
                        );
                    } 
                    else
                    {
                        var user = req.user;
                        user.google.id = profile.id;
                        user.google.token = token;
                        user.google.name = profile.displayName;
                        user.google.email = (profile.emails[0].value || '').toLowerCase();

                        user.save(
                            function(err) 
                            {
                                if (err)
                                    return done(err);
                                return done(null, user);
                            }
                        );
                    }
                }
            );
        }
    ));
    // =========================================================================
    // Vkontakte ==================================================================
    // =========================================================================
    passport.use(new VkontakteStrategy(
        {
            clientID : configAuth.vkontakteAuth.clientID,
            clientSecret : configAuth.vkontakteAuth.clientSecret,
            callbackURL : configAuth.vkontakteAuth.callbackURL,
            passReqToCallback : true
        },
        function(req, token, refreshToken, params, profile, done) 
        {
            process.nextTick(
                function() 
                {
                    if (!req.user) 
                    {
                        User.findOne(
                            {
                                'vkontakte.id' : profile.id 
                            },
                            function(err, user) 
                            {
                                if (err)
                                    return done(err);

                                if (user)
                                {
                                    if (!user.vkontakte.token) 
                                    {
                                        user.vkontakte.token = token;
                                        user.vkontakte.name  = profile.displayName;
                                        user.vkontakte.email = (params.email || '').toLowerCase();
                                        user.save(
                                            function(err) 
                                            {
                                                if (err)
                                                    return done(err);
                                                    
                                                return done(null, user);
                                            }
                                        );
                                    }
                                    return done(null, user);
                                } 
                                else
                                {
                                    var newUser = new User();
                                    newUser.vkontakte.id = profile.id;
                                    newUser.vkontakte.token = token;
                                    newUser.vkontakte.name = profile.displayName;
                                    newUser.vkontakte.email = (params.email || '').toLowerCase();
                                    
                                    newUser.save(
                                        function(err)
                                        {
                                            if (err)
                                                return done(err);
                                            return done(null, newUser);
                                        }
                                    );
                                }
                            }
                        );
                    } 
                    else
                    {
                        var user = req.user;
                        user.vkontakte.id = profile.id;
                        user.vkontakte.token = token;
                        user.vkontakte.name = profile.displayName;
                        user.vkontakte.email = (params.email.value || '').toLowerCase();

                        user.save(
                            function(err) 
                            {
                                if (err)
                                    return done(err);
                                return done(null, user);
                            }
                        );
                    }
                }
            );
        }
    ));

};
