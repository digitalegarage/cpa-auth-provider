"use strict";

var db = require('../../models');
var authHelper = require('../../lib/auth-helper');
var socialLoginHelper = require('../../lib/social-login-helper');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');


var routes = function (router) {

    router.get('/user/devices', authHelper.authenticateFirst, function (req, res, next) {
        db.Client
            .findAll({
                where: {user_id: req.user.id},
                include: [
                    db.User,
                    {model: db.AccessToken, include: [db.Domain]},
                    {model: db.PairingCode, include: [db.Domain]}
                ],
                order: [['id']]
            })
            .then(function (clients) {
                var flash = {};
                if (req.session.flashMessage) {
                    flash.message = req.session.flashMessage;
                    flash.type = 'info';
                    delete req.session.flashMessage;
                }
                return res.render('./user/devices.ejs', {devices: clients, flash: flash});
            }, function (err) {
                next(err);
            });
    });

    router.get('/user/profile', recaptcha.middleware.render, authHelper.authenticateFirst, function (req, res) {
        var user = req.user;
        if (!user) {
            return res.status(401).send({msg: req.__('BACK_PROFILE_AUTH_FAIL')});
        } else {
            socialLoginHelper.getSocialEmails(user).then(function (emails) {
                var socialEmail = (emails && emails.length > 0) ? emails[0] : "";
                socialLoginHelper.getSocialLogins(user).then(function (logins) {
                    var email = user.LocalLogin ? user.LocalLogin.login : undefined;
                    var data = {
                        profile: {
                            login: email,
                            firstname: user.firstname,
                            lastname: user.lastname,
                            gender: user.gender,
                            language: user.language,
                            date_of_birth: user.date_of_birth_ymd ? user.date_of_birth_ymd : null,
                            email: email,
                            socialEmail: socialEmail,
                            display_name: user.getDisplayName(req.query.policy, email),
                            verified: !user.LocalLogin || user.LocalLogin.verified,
                            hasPassword: user.LocalLogin && !!user.LocalLogin.password,
                            facebook: logins.indexOf(socialLoginHelper.FB) > -1,
                            google: logins.indexOf(socialLoginHelper.GOOGLE) > -1,
                            hasSocialLogin: logins.length > 0,
                            public_uid: user.public_uid
                        },
                        captcha: req.recaptcha
                    };
                    data.flash = {};
                    if (req.session.flashMessage) {
                        data.flash.message = req.session.flashMessage;
                        data.flash.type = "success";
                        delete req.session.flashMessage;
                    }
                    res.render('./user/profile.ejs', data);
                });
            });
        }
    });

};

module.exports = routes;
