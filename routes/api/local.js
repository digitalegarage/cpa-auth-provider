"use strict";

var db = require('../../models');
var config = require('../../config');

var passport = require('passport');

var JwtStrategy = require('passport-jwt').Strategy,
    ExtractJwt = require('passport-jwt').ExtractJwt;

//TODO move or delete the following
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

};
