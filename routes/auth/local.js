"use strict";

var db = require('../../models');
var config = require('../../config');
var afterLogoutHelper = require('../../lib/afterlogout-helper');
var requestHelper = require('../../lib/request-helper');
var finder = require('../../lib/finder');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');


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
};
