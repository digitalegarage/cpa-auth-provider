"use strict";

var db = require('../../models');
var config = require('../../config');

var passport = require('passport');

var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;
var cors = require('../../lib/cors');

var emailHelper = require('../../lib/email-helper');
var authHelper = require('../../lib/auth-helper');

var codeHelper = require('../../lib/code-helper');
var limiterHelper = require('../../lib/limiter-helper');
var userHelper = require ('../../lib/user-helper');


var opts = {};
opts.jwtFromRequest = ExtractJwt.fromExtractors(
    [
        ExtractJwt.fromAuthHeaderWithScheme('JWT'),
        ExtractJwt.fromAuthHeaderAsBearerToken()
    ]
);
opts.secretOrKey = config.jwtSecret;
// opts.issuer = "accounts.examplesoft.com";
// opts.audience = "yoursite.net";
passport.use(new JwtStrategy(opts, function (jwt_payload, done) {
    if (!jwt_payload) {
        done(null, false);
        return;
    }
    db.User.findOne({where: {id: jwt_payload.id}, include: [db.LocalLogin]})
        .then(function (user) {
            if (user) {
                done(null, user);
            } else {
                done(null, false);
            }
        });
}));

module.exports = function (app, options) {

    app.post('/api/local/password/recover', cors, limiterHelper.verify, function (req, res, next){
        userHelper.password_recover(req)
        .then(()=>{
            res.sendStatus(204);
        })
        .catch((err)=> {
            next(err);
        });
    });

    // This is needed because when configuring a custom header JQuery automaticaly send options request to the server.
    // That following line avoid cross domain error like
    // XMLHttpRequest cannot load http://localhost.rts.ch:3000/api/local/info.
    // Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.
    // Origin 'http://localhost.rts.ch:8090' is therefore not allowed access.
    app.options('/api/local/info', cors);

    app.get('/api/local/info', cors, passport.authenticate('jwt', {session: false}), function (req, res) {
        var user = req.user;
        if (!user) {
            return res.status(403).send({success: false, msg: req.__('API_INCORRECT_LOGIN_OR_PASS')});
        } else {
            var data = {};
            if (user.LocalLogin) {
                data.email = user.LocalLogin.login;
                data.display_name = user.getDisplayName(req.query.policy, user.LocalLogin.login);
            } else {
                data.display_name = user.getDisplayName(req.query.policy, '');
            }
            res.json({
                success: true,
                user: data,
            });
        }
    });

    app.get('/api/local/request_verification_email', cors, passport.authenticate('jwt', {session: false}), function (req, res) {

        var user = authHelper.getAuthenticatedUser(req);

        if (!user) {
            return res.status(403).send({success: false, msg: req.__('API_VERIF_MAIL_NOT_AUTH')});
        } else {
            return codeHelper.getOrGenereateEmailVerificationCode(user).then(function (code) {

                emailHelper.send(
                    config.mail.from,
                    user.LocalLogin ? user.LocalLogin.login : '',
                    "validation-email",
                    {log: false},
                    {
                        confirmLink: config.mail.host + '/email_verify?email=' + encodeURIComponent(user.LocalLogin ? user.LocalLogin.login : '') + '&code=' + encodeURIComponent(code),
                        host: config.mail.host,
                        mail: user.LocalLogin ? user.LocalLogin.login : '',
                        code: user.verificationCode
                    },
                    user.language ? user.language : config.mail.local
                ).then(
                    function () {
                    },
                    function (err) {
                    }
                );
                return res.status(204).send({success: true, msg: req.__('API_VERIF_MAIL_SENT')});
            });
        }
    });
};
