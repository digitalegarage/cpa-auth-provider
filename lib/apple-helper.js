"use strict";

const socialLoginHelper = require ('../lib/social-login-helper');
const db = require('../models/index');
const appleSignin = require('apple-signin');

function handleAppleToken(result, req, next, res) {
    const userAppleId = result.sub;
    const email = result.email;
    return socialLoginHelper.findOrCreateSocialLoginUser(socialLoginHelper.APPLE, email, userAppleId, userAppleId, null, null, null, null).then(
        function(user) {
            if (user) {
                db.SocialLogin.findOne({
                    where: {
                        user_id: user.id,
                        name: socialLoginHelper.APPLE
                    }
                }).then(function(socialLogin) {
                    socialLogin.logLogin(user);
                }).then(function() {
                    return req.session.regenerate(function(err) {
                        if (err) {
                            next(err);
                        } else {
                            return req.logIn(user, function() {
                                req.session.save();
                                return socialLoginHelper.afterSocialLoginSucceed(req, res);
                            });
                        }
                    });
                });
            }
        }).catch((err) => {
        next(err);
    });
}

function verifyIdToken(id_token, client_id){
    return appleSignin.verifyIdToken(id_token, client_id);
}

module.exports = {
    handleAppleToken: handleAppleToken,
    verifyIdToken: verifyIdToken
};