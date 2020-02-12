"use strict";

var db = require('../models');
var config = require('../config');
var permissionName = require('./permission-name');


var authHelper = require('./auth-helper');
var i18n = require('i18n');

var appHelper = {};
var sessionHelper = require('./session-helper');
var store;
var sequelize = require('sequelize');
var Op = sequelize.Op;

var _ = require('underscore');
var Session;

appHelper.sessionOptions = function (express) {
    var options = {};

    if (process.env.NODE_ENV === 'test') {
        options.secret = config.session_secret;
        options.cookie = {
		    sameSite: config.auth_session_cookie.sameSite || 'lax'
	    };
    } else {
        var session = require('express-session');
        if (config.use_sequelize_sessions) {
            console.log("Setting up sessions");
            Session = db.sequelize.define('Session', {
                sid: {
                    type: sequelize.STRING,
                    primaryKey: true,
                    field: "sid",
                },
                userId: sequelize.STRING,
                expires: sequelize.DATE,
                data: sequelize.STRING(config.auth_session_cookie.session_data_length || 10000)
            },
            {
                indexes: [
                    {
                        name: 'sessions_expire_idx',
                        fields: ['expires']
                    }
                ]
            });
            Session.removeAttribute('id');

            var SequelizeStore = require('connect-session-sequelize')(session.Store);
            sessionHelper.handleSequelizeStore(SequelizeStore, session);
            store = new SequelizeStore({db: db.sequelize, table: 'Session', extendDefaultFields: extendDefaultFields});
            store.sync();
        } else {
            var SQLiteStore = require('connect-sqlite3')(session);
            sessionHelper.handleSqliteStore(SQLiteStore, session);
            store = new SQLiteStore();
        }

        options.store = store;
        options.secret = config.session_secret;
        options.checkExpirationInterval = 24 * 60 * 60 * 1000;

        // cookie's parameters
        options.cookie = {
            maxAge: config.auth_session_cookie.duration || 7 * 24 * 60 * 60 * 1000,
            httpOnly: !config.auth_session_cookie.js_accessible,
            secure: !config.auth_session_cookie.accessible_over_non_https,
            domain: config.auth_session_cookie.domain,
            sameSite: config.auth_session_cookie.sameSite || 'lax'
        };
        // Override the default cookie name ('connect.sid') so another node
        // running on the same host (with different port) won't be able to update that cookie
        options.name = config.auth_session_cookie.name || 'identity.provider.sid';

    }

    options.resave = true;
    options.saveUninitialized = true;

    require('./clean-session').start();

    return options;
};

appHelper.destroySessionsByUserId = function(userId,excludeId) {
    return new Promise(function(resolve,reject) {
        if (store != null){ // Might be null in tests
            store.deleteByUserId(userId, excludeId, function(err,result) {
                if (err){
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        } else {
            resolve();
        }
    });
};

appHelper.destroyNotLoggedSessions = function(logger) {
    return new Promise(function(resolve,reject) {
        if (Session != null){ // Might be null in tests
            Session.destroy({
                where: {
                    userId: {
                        [Op.or]: ['', null]
                    },
                    createdAt: {
                        [Op.lt]: new Date(Date.now() - (24 * 60 * 60 * 1000)),
                    }
                }
            })
            .then((res)=> {
                logger.info("Session cleaned:" , res);
                resolve();
            });
        } else {
            resolve();
        }
    });
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
            include: [db.Permission, db.LocalLogin]
        }).then(function (user) {
                done(null, user);
            },
            function (error) {
                done(error, null);
            });
    });
};

appHelper.headerHelper = function (app, logger) {
    // iframe options
    app.use(function (req, res, next) {
        var option_string = 'DENY';
        if (config.iframes && config.iframes.option) {
            switch (config.iframes.option.toLowerCase()) {
                case 'sameorigin':
                    option_string = 'SAMEORIGIN';
                    break;
                case 'deny':
                    option_string = 'DENY';
                    break;
                case 'allow-from':
                    if (config.iframes.allow_from_domain) {
                        option_string = 'ALLOW-FROM ' + config.iframes.allow_from_domain;
                    } else {
                        logger.error("IFRAME OPTIONS: ALLOW-FROM is set, but no allow_from_domain were given! Denying all!");
                        option_string = 'DENY'; // safe fallback?
                    }
                    break;
                case 'unset':
                    option_string = undefined;
                    break;
                default:
                    logger.warn("Cannot set your option '" + config.iframes.option + "', will deny all x-iframes.");
                    option_string = 'DENY';
            }
            if (option_string)
                res.append('X-Frame-Options', option_string);
            logger.info("HEADER FRAME OPTIONS: Set to " + option_string);
        }
        // set various other options
        if (config.use_secure_headers) {

            var additionnalScripts = config.content_security_policy && config.content_security_policy.additional_scripts_src ? ' ' + config.content_security_policy.additional_scripts_src : '';
            var additionnalStyles = config.content_security_policy && config.content_security_policy.additional_styles_src ? ' ' + config.content_security_policy.additional_styles_src : '';
            var additionnalFrames = config.content_security_policy && config.content_security_policy.additional_frames_src ? ' ' + config.content_security_policy.additional_frames_src : '';
            var additionnalFonts = config.content_security_policy && config.content_security_policy.additional_fonts_src ? ' ' + config.content_security_policy.additional_fonts_src : '';

            // Unless you have to load font using AJAX and set it directly as B64 in a font HTML tag, it's not recommended to enable allow_fonts_data
            var data = config.content_security_policy && config.content_security_policy.allow_fonts_data ? ' data:' : '';

            res.append('X-XSS-Protection', '1; mode=block');
            res.append('X-Content-Type-Options', 'nosniff');
            res.append('Strict-Transport-Security', 'max-age=31536000');
            res.append('Content-Security-Policy', 'default-src data: https: \'self\';' +
                ' script-src https: \'self\' \'unsafe-inline\' http://connect.facebook.com/' + additionnalScripts + ';' +
                ' style-src https: \'self\' \'unsafe-inline\'' + additionnalStyles + ';' +
                ' img-src *;' +
                ' frame-src \'self\' http://staticxx.facebook.com https://www.google.com https://accounts.google.com/' + additionnalFrames + ';' +
                ' connect-src https:;' +
                ' font-src' + data + ' \'self\'' + additionnalFonts);
            logger.info("HEADER OPTIONS: More secure http header options are set.");
        } else {
            logger.info("HEADER OPTIONS: More secure http header options are NOT set.");
        }
        next();
    });
    // remove not needed header
    app.disable('x-powered-by');

};

function extendDefaultFields(defaults, session) {
    return {
        data: defaults.data,
        expires: defaults.expires,
        userId: (session && session.passport && session.passport.user) ? session.passport.user : ''
    };
}

module.exports = appHelper;
