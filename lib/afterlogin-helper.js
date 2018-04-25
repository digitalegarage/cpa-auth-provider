"use strict";

var config = require('../config');

function afterLogin(user, res){
    if (config.afterLogin && config.afterLogin.storeUserInfoInCookie && config.afterLogin.storeUserInfoInCookie.activated){
        var value = {};
        if (config.afterLogin.storeUserInfoInCookie.storeUserId){
            value.userId = user.id;
        }
        if (config.afterLogin.storeUserInfoInCookie.storeUserDisplayName){
            value.userId =  user.getDisplayName() || user.LocalLogin.login;
        }
        res.cookie(config.afterLogin.storeUserInfoInCookie.cookieName, JSON.stringify(value), {
            maxAge: config.afterLogin.storeUserInfoInCookie.duration,
            httpOnly: false,
            domain: config.afterLogin.storeUserInfoInCookie.domain
        });
    }
}

module.exports = {
    afterLogin: afterLogin,
};