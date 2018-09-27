"use strict";

var config = require('../../config');
var authHelper = require('../../lib/auth-helper');
var requestHelper = require('../../lib/request-helper');
let afterLogoutHelper = require('../../lib/afterlogout-helper');

module.exports = function (router) {
    router.get('/logout', function (req, res) {
        afterLogoutHelper.afterLogout(res);
        req.session.destroy();
        req.logout();
        requestHelper.redirect(res, '/');
    });

    router.get('/protected', authHelper.authenticateFirst, function (req, res) {
        res.send('protected');
    });

    authHelper.loadIdentityProviders(router, config.identity_providers);

};
