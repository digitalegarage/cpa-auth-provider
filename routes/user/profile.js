"use strict";

var config = require('../../config');
var db = require('../../models/index');
var authHelper = require('../../lib/auth-helper');
var util = require('util');
var xssFilters = require('xss-filters');
var emailHelper = require('../../lib/email-helper');
var recaptcha = require('express-recaptcha');
var codeHelper = require('../../lib/code-helper');
var i18n = require('i18n');
var userHelper = require('../../lib/user-helper');

var routes = function (router) {
    router.put('/user/profile/', authHelper.ensureAuthenticated, function (req, res) {
        var userId = authHelper.getAuthenticatedUser(req).id;

        var requiredFields = userHelper.getRequiredFields();
        if (requiredFields.firstname) {
            req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).notEmpty().isAlpha();
        } else if (req.body.firstname) {
            req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).isAlpha();
        }
        if (requiredFields.lastname) {
            req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).notEmpty().isAlpha();
        } else if (req.body.lastname) {
            req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).isAlpha();
        }
        if (requiredFields.birthdate) {
            req.checkBody('birthdate', req.__('BACK_PROFILE_UPDATE_BIRTHDATE_EMPTY_OR_INVALID')).notEmpty().isInt();
        } else if (req.body.birthdate) {
            req.checkBody('birthdate', req.__('BACK_PROFILE_UPDATE_BIRTHDATE_EMPTY_OR_INVALID')).isInt();
        }
        if (requiredFields.gender) {
            req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).notEmpty().isIn(['male', 'female']);
        } else if (req.body.gender) {
            req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).isIn(['male', 'female']);
        }
        if (requiredFields.language) {
            req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).notEmpty().isAlpha();
        } else if (req.body.language) {
            req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).isAlpha();
        }

        req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                res.status(400).json({errors: result.array()});
                return;
            }
            userHelper.updateProfile(authHelper.getAuthenticatedUser(req), req.body).then(
                function (userProfile) {
                    res.cookie(config.i18n.cookie_name, userProfile.language, {
                        maxAge: config.i18n.cookie_duration,
                        httpOnly: true
                    });
                    res.json({msg: req.__('BACK_PROFILE_UPDATE_SUCCESS')});
                },
                function (err) {
                    console.log(err);
                    res.status(500).json({msg: req.__('BACK_PROFILE_UPDATE_FAIL') + err});
                }
            );
        });
    });

    router.post('/user/profile/request_verification_email', [authHelper.ensureAuthenticated, recaptcha.middleware.verify], function (req, res) {
        if (req.recaptcha.error)
            return res.status(400).json({msg: 'reCaptcha is empty or wrong. '});

        var user = authHelper.getAuthenticatedUser(req);
        if (!user) {
            return res.status(403).send({success: false, msg: req.__('BACK_PROFILE_REQ_VERIF_MAIL')});
        } else {
            codeHelper.getOrGenereateEmailVerificationCode(user).then(function (code) {
                emailHelper.send(
                    config.mail.from,
                    user.email,
                    "validation-email",
                    {log: false},
                    {
                        confirmLink: config.mail.host + '/email_verify?email=' + encodeURIComponent(user.email) + '&code=' + encodeURIComponent(code),
                        host: config.mail.host,
                        mail: encodeURIComponent(user.email),
                        code: encodeURIComponent(code)
                    },
                    (user.UserProfile && user.UserProfile.language) ? user.UserProfile.language : req.getLocale()
                ).then(
                    function () {
                    },
                    function () {
                    }
                );
            });
            return res.status(204).send();
        }
    });

    router.post('/user', authHelper.ensureAuthenticated, function (req, res) {

        var user = authHelper.getAuthenticatedUser(req);

        //If facebook user then we do not check for account password as it can be empty
        if (!user.password && (user.isFacebookUser() || user.isGoogleUser())) {

            user.destroy();
            return res.status(204).send();
        }

        user.verifyPassword(req.body.password).then(function (isMatch) {
                if (isMatch) {
                    return user.destroy();
                } else {
                    if (req.body.password) {
                        throw new Error(req.__('PROFILE_API_DELETE_YOUR_ACCOUNT_WRONG_PASSWORD'));
                    } else {
                        throw new Error(req.__('PROFILE_API_DELETE_YOUR_ACCOUNT_MISSING_PASSWORD'));
                    }
                }
            }
        ).then(function () {
            return res.status(204).send();
        }).catch(function (e) {
            res.status(401).send({success: false, msg: e.message});
        });
    });
};

module.exports = routes;
