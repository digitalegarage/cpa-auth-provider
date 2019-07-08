"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');

var emailHelper = require('../../lib/email-helper');
var passwordHelper = require('../../lib/password-helper');
var limiterHelper = require('../../lib/limiter-helper');
var afterLogoutHelper = require('../../lib/afterlogout-helper');
var requestHelper = require('../../lib/request-helper');

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

};
