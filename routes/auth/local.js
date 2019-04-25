"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');

var emailHelper = require('../../lib/email-helper');
var codeHelper = require('../../lib/code-helper');
var passwordHelper = require('../../lib/password-helper');
var finder = require('../../lib/finder');
var limiterHelper = require('../../lib/limiter-helper');
var afterLogoutHelper = require('../../lib/afterlogout-helper');
var requestHelper = require('../../lib/request-helper');
var apiErrorHelper = require('../../lib/api-error-helper');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');
var i18n = require('i18n');


module.exports = function (app, options) {

    // DO NOT REMOVE ENDPOINT : used for backward compatibility with laboutique.rts.ch
    app.get('/auth/custom', recaptcha.middleware.render, function (req, res) {

        db.OAuth2Client.findOne({where: {client_id: req.query.client_id}}).then(function (client) {
            if (client) {
                var redirect = encodeURIComponent("/oauth2/dialog/authorize?" +
                    "defaultLanguage=fr" +
                    "&response_type=code&approval_prompt=auto" +
                    "&client_id=" + client.client_id +
                    "&display=popup" +
                    "&redirect_uri=" + encodeURIComponent(client.redirect_uri));
                requestHelper.redirect(res, '/login?redirect=' + redirect);
            } else {
                res.json({'error': 'Unknown client id' + req.query.client_id});
            }
        });

    });

    app.get('/password/edit', function (req, res) {
        if (config.broadcaster.changeRecoverPasswordPage) {
            var queryString = 'email='+req.query.email+'&code='+req.query.code;
            if (config.broadcaster.changeRecoverPasswordPage.indexOf('?') >= 0) {
                return res.redirect(config.broadcaster.changeRecoverPasswordPage + '&'+ queryString);
            } else {
                return res.redirect(config.broadcaster.changeRecoverPasswordPage + '?' + queryString);
            }
        } else {
            res.render('password-edit.ejs', {email: req.query.email, code: req.query.code});
        }
    });

    // For AJAX call use DELETE method on /api/v2/session/logout in order to avoid have 304 unmodified and user no disconnected
    app.get('/logout', function (req, res, next) {
        req.logout();
        req.session.regenerate(function (err) {
            if (err) {
                next(err);
            } else {
                afterLogoutHelper.afterLogout(res);
                requestHelper.redirect(res, '/');
            }
        });
    });

    app.get('/email_verify', function (req, res, next) {

        finder.findUserByLocalAccountEmail(req.query.email).then(function (localLogin) {
            if (localLogin) {
                codeHelper.verifyEmail(localLogin, req.query.code).then(function (success) {
                        if (success) {
                            if (config.broadcaster.changeEmailConfirmationPage) {
                                if (config.broadcaster.changeEmailConfirmationPage.indexOf('?') >= 0) {
                                    return res.redirect(config.broadcaster.changeEmailConfirmationPage + '&success=true');
                                } else {
                                    return res.redirect(config.broadcaster.changeEmailConfirmationPage + '?success=true');
                                }
                            } else {
                                    res.render('./verify-mail.ejs', {
                                        verified: localLogin.verified,
                                        userId: localLogin.user_id
                                    });
                            }
                        } else {
                            if (config.broadcaster.changeEmailConfirmationPage) {
                                if (config.broadcaster.changeEmailConfirmationPage.indexOf('?') >= 0) {
                                    return res.redirect(config.broadcaster.changeEmailConfirmationPage + '&success=false');
                                } else {
                                    return res.redirect(config.broadcaster.changeEmailConfirmationPage + '?success=false');
                                }
                            } else {
                                res.render('./verify-mail.ejs', {verified: false});
                            }
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
                                forceLink: requestHelper.getIdpRoot() + '/password/edit?email=' + encodeURIComponent(localLogin.login) + '&code=' + encodeURIComponent(code),
                                host: requestHelper.getIdpRoot(),
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
                next(apiErrorHelper.buildError(400, 'VALIDATION_ERROR', 'Validation error', '',[], result.array()));
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

};
