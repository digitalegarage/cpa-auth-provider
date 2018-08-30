"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');

var passport = require('passport');

var emailHelper = require('../../lib/email-helper');
var codeHelper = require('../../lib/code-helper');
var passwordHelper = require('../../lib/password-helper');
var finder = require('../../lib/finder');
var userHelper = require('../../lib/user-helper');
var limiterHelper = require('../../lib/limiter-helper');
var afterLoginHelper = require('../../lib/afterlogin-helper');
var authLocalHelper = require('../../lib/auth-local-helper');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');
var i18n = require('i18n');


var localStrategyConf = {
    // by default, local strategy uses username and password, we will override with email
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true // allows us to pass back the entire request to the callback
};

passport.use('local', new LocalStrategy(localStrategyConf, authLocalHelper.localStrategyCallback));

passport.use('local-signup', new LocalStrategy(localStrategyConf, authLocalHelper.localSignupStrategyCallback));

module.exports = function (app, options) {

    app.get('/auth/local', function (req, res) {
        var message = {};
        if (req.query && req.query.error) {
            message = req.__(req.query.error);
        }
        var loginMessage = req.flash('loginMessage');
        if (loginMessage && loginMessage.length > 0) {
            message = loginMessage;
        }
        res.render('login.ejs', {message: message});
    });
    app.get('/auth/custom', recaptcha.middleware.render, function (req, res) {
        var required = userHelper.getRequiredFields();
        var profileAttributes = {
            captcha: req.recaptcha,
            requiredFields: required,
            message: req.flash('signupMessage'),
            auth_origin: req.session.auth_origin,
            client_id: req.query.client_id
        };

        db.OAuth2Client.findOne({where: {client_id: req.query.client_id}}).then(function (client) {
            if (client && client.use_template) {
                res.render('broadcaster/' + client.use_template + '/custom-login-signup.ejs', profileAttributes);
            } else {
                // No client found or no dedicated login window => redirect to login '/auth/local'
                res.render('login.ejs', {message: ''});
            }
        });

    });

    app.get('/signup', recaptcha.middleware.render, function (req, res) {
        var required = userHelper.getRequiredFields();
        var profileAttributes = {
            email: req.query.email ? decodeURIComponent(req.query.email) : '',
            captcha: req.recaptcha,
            requiredFields: required,
            message: req.flash('signupMessage')
        };
        for (var key in required) {
            if (required.hasOwnProperty(key) && required[key]) {
                profileAttributes[key] = req.query[key] ? decodeURIComponent(req.query[key]) : '';
            }
        }
        res.render('signup.ejs', profileAttributes);
    });

    app.get('/password/recovery', recaptcha.middleware.render, function (req, res) {
        res.render('password-recovery.ejs', {captcha: req.recaptcha});
    });

    app.get('/password/edit', function (req, res) {
        res.render('password-edit.ejs', {email: req.query.email, code: req.query.code});
    });

    app.get('/logout', function (req, res) {
        req.logout();
        req.session.destroy();
        requestHelper.redirect(res, '/');
    });

    app.get('/email_verify', function (req, res, next) {

        finder.findUserByLocalAccountEmail(req.query.email).then(function (localLogin) {
            if (localLogin) {
                codeHelper.verifyEmail(localLogin, req.query.code).then(function (success) {
                        if (success) {
                            res.render('./verify-mail.ejs', {
                                verified: localLogin.verified,
                                userId: localLogin.user_id
                            });
                        } else {
                            res.render('./verify-mail.ejs', {verified: false});
                        }
                    }
                );
            } else {
                return res.status(400).json({msg: req.__('BACK_SIGNUP_EMAIL_VERIFY_USER_NOT_FOUND')});
            }
        }, function (error) {
            next(error);
        });
    });

    app.post('/login', passport.authenticate('local', {
        failureRedirect: config.urlPrefix + '/auth/local',
        failureFlash: true
    }), redirectOnSuccess);

    app.post('/signup', limiterHelper.verify, function (req, res, next) {

        passport.authenticate('local-signup', function (err, user, info) {

            if (req.recaptcha.error) {
                return requestHelper.redirect(res, '/signup?error=recaptcha');
            }
            if (err) {
                return next(err);
            }
            // Redirect if it fails
            if (!user) {
                var params = ['email=' + encodeURIComponent(req.body.email)];
                if (config.userProfiles && config.userProfiles.requiredFields) {
                    for (var i = 0; i < config.userProfiles.requiredFields.length; ++i) {
                        var element = config.userProfiles.requiredFields[i];
                        params.push(element + "=" + encodeURIComponent(req.body[element]));
                    }
                }
                return requestHelper.redirect(res, '/signup?' + params.join('&'));
            }
            req.logIn(user, function (err) {
                if (err) {
                    return next(err);
                }
                // Redirect if it succeeds
                return redirectOnSuccess(req, res, next);
            });
        })(req, res, next);
    });

    app.post('/password/code', limiterHelper.verify, function (req, res, next) {

        if (req.recaptcha.error) {
            return res.status(400).json({msg: req.__('BACK_SIGNUP_PWD_CODE_RECAPTCHA_EMPTY_OR_WRONG')});
        }

        req.checkBody('email', req.__('BACK_SIGNUP_EMAIL_EMPTY_OR_INVALID')).isEmail();

        req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                res.status(400).json({errors: result.array()});
                return;
            }


            finder.findUserByLocalAccountEmail(req.body.email).then(function (localLogin) {
                if (localLogin) {
                    codeHelper.generatePasswordRecoveryCode(localLogin.user_id).then(function (code) {
                        emailHelper.send(
                            config.mail.from,
                            localLogin.login,
                            "password-recovery-email",
                            {log: false},
                            {
                                forceLink: config.mail.host + config.urlPrefix + '/password/edit?email=' + encodeURIComponent(localLogin.login) + '&code=' + encodeURIComponent(code),
                                host: config.mail.host,
                                mail: encodeURIComponent(localLogin.login),
                                code: encodeURIComponent(code)
                            },
                            localLogin.User.language ? localLogin.User.language : i18n.getLocale()
                        ).then(
                            function () {
                            },
                            function (err) {
                            }
                        );
                        return res.status(200).send();
                    });
                } else {
                    return res.status(400).json({msg: req.__('BACK_SIGNUP_USER_NOT_FOUND')});
                }
            }, function (error) {
                next(error);
            });
        });

    });

    app.post('/password/update', function (req, res, next) {

        req.checkBody('password', req.__('BACK_PWD_UPDATE_PWD_EMPTY')).notEmpty();
        req.checkBody('confirm-password', req.__('BACK_PWD_UPDATE_CONF_PWD_EMPTY')).notEmpty();
        req.checkBody('confirm-password', req.__('BACK_PWD_UPDATE_PWD_DONT_MATCH_EMPTY')).equals(req.body.password);

        req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                res.status(400).json({errors: result.array()});
                return;
            }

            if (!passwordHelper.isStrong(req.body.email, req.body.password)) {
                res.status(400).json({
                    errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}],
                    password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                    score: passwordHelper.getQuality(req.body.email, req.body.password)
                });
                return;
            } else {
                finder.findUserByLocalAccountEmail(req.body.email).then(function (localLogin) {
                    if (localLogin && localLogin.User) {
                        return codeHelper.recoverPassword(localLogin.User, req.body.code, req.body.password).then(function (success) {
                            if (success) {
                                return res.status(200).send();
                            } else {
                                return res.status(400).json({msg: req.__('BACK_PWD_WRONG_RECOVERY_CODE')});
                            }
                        });
                    }
                    else {
                        return res.status(400).json({msg: req.__('BACK_PWD_UPDATE_USER_NOT_FOUND')});
                    }
                }, function (error) {
                    next(error);
                });
            }
        });

    });

    function redirectOnSuccess(req, res, next) {
        var redirectUri = req.session.auth_origin;
        delete req.session.auth_origin;

        if (req.session.callback_url) {
            redirectUri = req.session.callback_url;
            delete req.session.callback_url;
        }

        afterLoginHelper.afterLogin(req.user, req.body.email || req.query.email, res);

        req.session.save(
            function () {
                if (redirectUri) {
                    return res.redirect(redirectUri);
                }

                return requestHelper.redirect(res, '/');
            }
        );
    }


};
