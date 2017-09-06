"use strict";

var db = require('../models');
var config = require('../config');
var permissionName = require('./permission-name');


var authHelper = require('./auth-helper');

var appHelper = {};

appHelper.sessionOptions = function (express) {
    var options = {};

    if (process.env.NODE_ENV === 'test') {
        options.secret = config.session_secret;
    }
    else {
        var session = require('express-session');
        var store = undefined;
        if (config.use_sequelize_sessions) {
            var SequelizeStore = require('connect-session-sequelize')(session.Store);
            store = new SequelizeStore({db: db.sequelize});
            store.sync();
        } else {
            var SQLiteStore = require('connect-sqlite3')(session);
            store = new SQLiteStore();
        }

        options.store = store;
        options.secret = config.session_secret;
        options.cookie = {maxAge: 7 * 24 * 60 * 60 * 1000};
        // Override the default cookie name ('connect.sid') so another node
        // running on the same host (with different port) won't be able to update that cookie
        options.name = config.sid_cookie_name || 'identity.provider.sid';
    }

    options.resave = false;
    options.saveUninitialized = true;

    return options;
};


appHelper.templateVariables = function (req, res, next) {

    // Add list of enabled idP
    res.locals.identity_providers = authHelper.getEnabledIdentityProviders();

    // Add user object to the template scope if authenticated
    res.locals.user = authHelper.getAuthenticatedUser(req);

    res.locals.language = req.getLocale();

    next();
};


appHelper.initPassportSerialization = function (passport) {
    // Init passport
    passport.serializeUser(function (user, done) {
        done(null, user.id);
    });

    passport.deserializeUser(function (id, done) {
        db.User.findOne({
            where: {id: id},
            include: [{model: db.Permission}, {model: db.UserProfile}]
        }).then(function (user) {
                done(null, user);
            },
            function (error) {
                done(error, null);
            });
    });
};

module.exports = appHelper;
