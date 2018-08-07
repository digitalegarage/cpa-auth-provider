"use strict";

var config = require('../config');

function afterLogout(res) {
    if (config.afterLogin && config.afterLogin.storeUserInfoInCookie && config.afterLogin.storeUserInfoInCookie.activated) {

        // expire cookie
        res.cookie(config.afterLogin.storeUserInfoInCookie.cookieName, '',
            {
                maxAge: new Date(0),
                httpOnly: false,
                domain: config.afterLogin.storeUserInfoInCookie.domain
            });
    }
}

module.exports = {
    afterLogout: afterLogout,
};