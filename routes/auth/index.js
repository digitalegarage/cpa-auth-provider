"use strict";

var config = require('../../config');
var authHelper = require('../../lib/auth-helper');

module.exports = function (router) {

    router.get('/protected', authHelper.authenticateFirst, function (req, res) {
        res.send('protected');
    });

    authHelper.loadIdentityProviders(router, config.identity_providers);

};
