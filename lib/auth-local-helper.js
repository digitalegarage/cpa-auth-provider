"use strict";

var finder = require('../lib/finder');

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


module.exports = {
    localStrategyCallback: localStrategyCallback,
};