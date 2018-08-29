"use strict";

var config = require('../../config');
var db = require('../../models');
var authHelper = require('../../lib/auth-helper');
var passwordHelper = require('../../lib/password-helper');
var requestHelper = require('../../lib/request-helper');
var socialLoginHelper = require('../../lib/social-login-helper');
var userHelper = require('../../lib/user-helper');
var logger = require('../../lib/logger');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');

var routes = function (router) {

    router.get('/user/devices', authHelper.authenticateFirst, function (req, res, next) {
        db.Client
            .findAll({
                where: {user_id: req.user.id},
                include: [
                    db.User,
                    {model: db.AccessToken, include: [db.Domain]},
                    {model: db.PairingCode, include: [db.Domain]}
                ],
                order: [['id']]
            })
            .then(function (clients) {
                var flash = {};
                if (req.session.flashMessage) {
                  flash.message = req.session.flashMessage;
                  flash.type = 'info';
                  delete req.session.flashMessage;
                }
                return res.render('./user/devices.ejs', {devices: clients, flash: flash});
            }, function (err) {
                next(err);
            });
    });

    router.get('/user/profile', recaptcha.middleware.render, authHelper.authenticateFirst, function (req, res) {
        var user = req.user;
        if (!user) {
            return res.status(401).send({msg: req.__('BACK_PROFILE_AUTH_FAIL')});
        } else {
            socialLoginHelper.getSocialEmails(user).then(function (emails) {
                var socialEmail = (emails && emails.length > 0) ? emails[0] : "";
                socialLoginHelper.getSocialLogins(user).then(function (logins) {
                    var email = user.LocalLogin ? user.LocalLogin.login : undefined;
                    var data = {
                        profile: {
                            login: email,
                            firstname: user.firstname,
                            lastname: user.lastname,
                            gender: user.gender,
                            language: user.language,
                            date_of_birth: user.date_of_birth_ymd ? user.date_of_birth_ymd : null,
                            email: email,
                            socialEmail: socialEmail,
                            display_name: user.getDisplayName(email, req.query.policy),
                            verified: !user.LocalLogin || user.LocalLogin.verified,
                            hasPassword: user.LocalLogin && !!user.LocalLogin.password,
                            facebook: logins.indexOf(socialLoginHelper.FB) > -1,
                            google: logins.indexOf(socialLoginHelper.GOOGLE) > -1,
                            hasSocialLogin: logins.length > 0
                        },
                        captcha: req.recaptcha
                    };
                    data.flash = {};
                    if (req.session.flashMessage) {
                      data.flash.message = req.session.flashMessage;
                      data.flash.type = "success";
                      delete req.session.flashMessage;
                    }
                    res.render('./user/profile.ejs', data);
                });
            });
        }
    });


    router.get('/responsive/login', recaptcha.middleware.render, function (req, res) {
        var data = {
            captcha: req.recaptcha,
            message: '',
            email: req.query.email ? req.query.email : '',
            target: requestHelper.getPath(req.query.redirect ? ('/api/v2/session/login' + '?redirect=' + req.query.redirect+'&code=true') : '/api/v2/session/login')
        };
        let broadcaster = config.broadcaster && config.broadcaster.name ? config.broadcaster.name + '/' : '/';
        res.render('./login/broadcaster/' + broadcaster + 'login.ejs', data);
    });


    router.post('/user/:user_id/password', authHelper.ensureAuthenticated, function (req, res) {
        req.checkBody('previous_password', req.__('BACK_CHANGE_PWD_PREV_PASS_EMPTY')).notEmpty();
        req.checkBody('password', req.__('BACK_CHANGE_PWD_NEW_PASS_EMPTY')).notEmpty();
        req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
        req.checkBody('password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

        req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                res.status(400).json({errors: result.array()});
            } else {
                var email = req.user.LocalLogin ? req.user.LocalLogin.login : "";
                if (!passwordHelper.isStrong(email, req.body.password)) {
                    res.status(400).json({
                        errors: [{msg: passwordHelper.getWeaknessesMsg(email, req.body.password, req)}],
                        password_strength_errors: passwordHelper.getWeaknesses(email, req.body.password, req),
                        score: passwordHelper.getQuality(email, req.body.password)
                    });
                } else {
                    db.User.findOne({
                        where: {
                            id: req.user.id
                        },
                        include: {
                            model: db.LocalLogin
                        }
                    }).then(function (user) {
                        if (!user) {
                            return res.status(401).send({errors: [{msg: req.__('BACK_USER_NOT_FOUND')}]});
                        } else {
                            user.LocalLogin.verifyPassword(req.body.previous_password).then(function (isMatch) {
                                // if user is found and password is right change password
                                if (isMatch) {
                                    user.LocalLogin.setPassword(req.body.password).then(
                                        function () {
                                            res.json({msg: req.__('BACK_SUCCESS_PASS_CHANGED')});
                                        },
                                        function (err) {
                                            res.status(500).json({errors: [err]});
                                        }
                                    );
                                } else {
                                    res.status(401).json({errors: [{msg: req.__('BACK_INCORRECT_PREVIOUS_PASS')}]});
                                }
                            });
                        }
                    });
                }
            }
        });
    });

    router.post('/user/:user_id/password/create', authHelper.ensureAuthenticated, function (req, res) {
        req.checkBody('email', req.__('BACK_CHANGE_PWD_MAIL_EMPTY')).notEmpty();
        req.checkBody('password', req.__('BACK_CHANGE_PWD_NEW_PASS_EMPTY')).notEmpty();
        req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
        req.checkBody('password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

        req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                res.status(400).json({errors: result.array()});
            } else {
                if (!passwordHelper.isStrong(req.body.email, req.body.password)) {
                    res.status(400).json({
                        errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}],
                        password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                        score: passwordHelper.getQuality(req.body.email, req.body.password)
                    });
                } else {
                    userHelper.addLocalLogin(req.user, req.body.email, req.body.password).then(
                        function () {
                            res.json({success: true, msg: req.__('BACK_SUCCESS_PASS_CREATED')});
                        },
                        function (err) {
                            if (err.message === userHelper.EXCEPTIONS.EMAIL_TAKEN) {
                                return res.status(400).json({
                                    success: false,
                                    msg: req.__('API_SIGNUP_EMAIL_ALREADY_EXISTS')
                                });
                            } else if (err.message === userHelper.EXCEPTIONS.PASSWORD_WEAK) {
                                return res.status(400).json({
                                    success: false,
                                    msg: req.__('API_SIGNUP_PASS_IS_NOT_STRONG_ENOUGH'),
                                    password_strength_errors: passwordHelper.getWeaknesses(req.body.email, req.body.password, req),
                                    errors: [{msg: passwordHelper.getWeaknessesMsg(req.body.email, req.body.password, req)}]
                                });
                            } else {
                                logger.error('[POST /user/:user_id/password/create][email', req.body.email, '][ERR', err, ']');
                                res.status(500).json({success: false, msg: req.__('API_ERROR') + err});
                            }
                        }
                    );
                }

            }
        });
    });


};

module.exports = routes;
