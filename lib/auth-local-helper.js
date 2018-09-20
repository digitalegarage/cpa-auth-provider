"use strict";

var config = require('../config');

var passwordHelper = require('../lib/password-helper');
var finder = require('../lib/finder');
var userHelper = require('../lib/user-helper');

var i18n = require('i18n');

var localStrategyCallback = function (req, username, password, done) {
    var loginError = req.__('BACK_SIGNUP_INVALID_EMAIL_OR_PASSWORD');

    finder.findUserByLocalAccountEmail(username).then(function (localLogin) {
            if (!localLogin) {
                doneWithError();
            } else {
                return localLogin.verifyPassword(password).then(function (isMatch) {
                        if (isMatch) {
                            localLogin.logLogin(localLogin.User);
                            done(null, localLogin.User);
                        } else {
                            doneWithError();
                        }
                    },
                    function (err) {
                        done(err);
                    });
            }
        },
        function (error) {
            done(error);
        });

    function doneWithError(e) {
        e = e || loginError;
        req.flash('loginMessage', e);
        req.session.save(function () {
            return done(null, false, e);
        });
    }
};

var localSignupStrategyCallback = function (req, username, password, done) {

    var optionnalAttributes = {};
    for (var element in userHelper.getRequiredFields()) {
        if (req.body[element] && !config.userProfiles.requiredFields.includes(element)) {
            optionnalAttributes[element] = req.body[element];
        }
    }

    var requiredAttributes = {};

    var required = userHelper.getRequiredFields();

    req.checkBody('email', req.__('BACK_SIGNUP_INVALID_EMAIL')).isEmail();
    req.checkBody('confirm_password', req.__('BACK_CHANGE_PWD_CONFIRM_PASS_EMPTY')).notEmpty();
    req.checkBody('password', req.__('BACK_CHANGE_PWD_PASS_DONT_MATCH')).equals(req.body.confirm_password);

    // general required copy
    for (var key in required) {
        if (required.hasOwnProperty(key) && required[key]) {
            requiredAttributes[key] = req.body[key];
        }
    }
    // specialized required copies
    if (required.gender) {
        req.checkBody('gender', req.__('BACK_SIGNUP_GENDER_FAIL')).notEmpty().isIn(['male', 'female', 'other']);
        requiredAttributes.gender = req.body.gender;
    }
    if (required.date_of_birth) {
        req.checkBody('date_of_birth', req.__('BACK_SIGNUP_DATE_OF_BIRTH_FAIL')).notEmpty().matches(/\d\d\/\d\d\/\d\d\d\d/);
        // date format is dd/mm/yyyy
        var parsed = /(\d\d)\/(\d\d)\/(\d\d\d\d)/.exec(req.body.date_of_birth);
        if (parsed) {
            var date = new Date(parsed[2] + '/' + parsed[1] + '/' + parsed[3]);
            requiredAttributes.date_of_birth = date.getTime();
        } else {
            requiredAttributes.date_of_birth = undefined;
        }
    }

    req.getValidationResult().then(function (result) {
            if (!result.isEmpty()) {
                result.useFirstErrorOnly();
                return doneWithError(result.array({onlyFirstError: true})[0].msg, done);
            } else {
                if (req.recaptcha.error) {
                    return doneWithError(req.__('BACK_SIGNUP_PB_RECAPTCHA'), done);
                }

                requiredAttributes.language = i18n.getLocale();
                userHelper.createLocalLogin(username, password, requiredAttributes, optionnalAttributes).then(
                    function (user) {
                        done(null, user);
                    },
                    function (err) {
                        if (err.message === userHelper.EXCEPTIONS.PASSWORD_WEAK) {
                            doneWithError(passwordHelper.getWeaknessesMsg(username, password, req), done);
                        } else if (err.message === userHelper.EXCEPTIONS.EMAIL_TAKEN) {
                            doneWithError(req.__('BACK_SIGNUP_EMAIL_TAKEN'), done);
                        } else if (err.message === userHelper.EXCEPTIONS.MISSING_FIELDS) {
                            // TODO properly log the missing fields ?
                            doneWithError(req.__('BACK_SIGNUP_MISSING_FIELDS'), done);
                        } else if (err.message === userHelper.EXCEPTIONS.UNKNOWN_GENDER) {
                            doneWithError(req.__('BACK_SIGNUP_MISSING_FIELDS'), done);
                        } else if (err.message === userHelper.EXCEPTIONS.MALFORMED_DATE_OF_BIRTH) {
                            doneWithError(req.__('BACK_SIGNUP_MISSING_FIELDS'), done);
                        } else {
                            done(err);
                        }
                    }
                );
            }
        }
    );

    function doneWithError(e, done) {
        req.flash('signupMessage', e);
        req.session.save(function () {
            done(null, false, e);
        });
    }
};



module.exports = {
    localStrategyCallback: localStrategyCallback,
    localSignupStrategyCallback: localSignupStrategyCallback
};