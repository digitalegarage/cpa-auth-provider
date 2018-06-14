"use strict";

var config = require('../../config');
var authHelper = require('../../lib/auth-helper');
var requestHelper = require('../../lib/request-helper');
var trackingCookie = require('../../lib/tracking-cookie');
let afterLogoutHelper = require('../../lib/afterlogout-helper');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');

module.exports = function (router) {
    router.get('/logout', function (req, res) {
        afterLogoutHelper.afterLogout(res);
        req.logout();
        requestHelper.redirect(res, '/');
    });

    router.get('/protected', authHelper.authenticateFirst, function (req, res) {
        res.send('protected');
    });

    router.get('/auth', trackingCookie.middleware, function (req, res) {
        var url;
        var autoIdpRedirect = config.auto_idp_redirect;

        if (req.session && req.session.auth_origin && req.session.client_id) {
            url = '/auth/custom?client_id=' + req.session.client_id;
        }
        if (!url && authHelper.validRedirect(autoIdpRedirect, config.identity_providers)) {
            url = '/auth/' + autoIdpRedirect;
            if (req.query && req.query.error) {
                url += "?error=" + req.query.error;
            }
        }
        if (!url) {
            res.render('./auth/provider_list.ejs');
            return;
        }

        requestHelper.redirect(res, url);
    });

    authHelper.loadIdentityProviders(router, config.identity_providers);

};
