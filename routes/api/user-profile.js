"use strict";

var db = require('../../models');
var config = require('../../config');
var passport = require('passport');
var cors = require('../../lib/cors');
var authHelper = require('../../lib/auth-helper');
var userHelper = require('../../lib/user-helper');
var apiErrorHelper = require('../../lib/api-error-helper');
var logger = require('../../lib/logger');

module.exports = function (app, options) {

    // This is needed because when configuring a custom header JQuery automaticaly send options request to the server.
    // That following line avoid cross domain error like
    // XMLHttpRequest cannot load http://localhost.rts.ch:3000/api/local/info.
    // Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.
    // Origin 'http://localhost.rts.ch:8090' is therefore not allowed access.
    app.options('/api/local/profile', cors);

    app.get('/api/local/profile', cors, passport.authenticate('jwt', {session: false}), function (req, res) {
        var user = authHelper.getAuthenticatedUser(req);

        if (!user) {
            apiErrorHelper.throwError(401, 'PROFILE_AUTHENTICATION_ERROR', 'Authentication error.', req.__('API_PROFILE_AUTH_FAIL'), [], {sucsess: false});
        } else {
            returnProfileAsJson(user, res, req);
        }
    });

    // A route for getting profile data when authed by a cpa token.
    app.get('/api/cpa/profile', function (req, res, next) {
        getCpaAuthedUser(req).then(function (user) {
            if (!user) {
                next(apiErrorHelper.buildError(401, 'PROFILE_CPA_AUTHENTICATION_ERROR', ' Cpa authentication error.'));
            } else {
                returnProfileAsJson(user, res, req);
            }
        }).catch(function (err) {
            next(apiErrorHelper.buildError(401, 'PROFILE_CPA_AUTHENTICATION_ERROR', ' Cpa authentication error.', '', [], err));
        });
    });

    // This is needed because when configuring a custom header JQuery automaticaly send options request to the server.
    // That following line avoid cross domain error like
    // XMLHttpRequest cannot load http://localhost.rts.ch:3000/api/local/info.
    // Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin' header is present on the requested resource.
    // Origin 'http://localhost.rts.ch:8090' is therefore not allowed access.
    app.options('/api/session/profile', cors);

    app.get('/api/session/profile', cors, authHelper.ensureAuthenticated, function (req, res) {
        var user = authHelper.getAuthenticatedUser(req);
        if (!user) {
            apiErrorHelper.throwError(401, 'PROFILE_SESSION_AUTHENTICATION_ERROR', 'Authentication error.', req.__('API_PROFILE_AUTH_FAIL'), [], {sucsess: false});
        } else {
            returnProfileAsJson(user, res, req);
        }
    });

    app.put('/api/local/profile', cors, passport.authenticate('jwt', {session: false}), function (req, res, next) {
        // Data validation
        if (req.body.firstname) {
            req.checkBody('firstname', req.__('API_PROFILE_FIRSTNAME_INVALIDE')).matches(userHelper.NAME_REGEX);
        }
        if (req.body.lastname) {
            req.checkBody('lastname', req.__('API_PROFILE_LASTNAME_INVALIDE')).matches(userHelper.NAME_REGEX);
        }
        if (req.body.date_of_birth) {
            req.checkBody('date_of_birth', req.__('API_PROFILE_DATE_OF_BIRTH_INVALIDE')).isInt();
        }
        if (req.body.gender) {
            req.checkBody('gender', req.__('API_PROFILE_GENDER_INVALIDE')).isIn(['male', 'female', 'other']);
        }
        if (req.body.language) {
            req.checkBody('language', req.__('API_PROFILE_LANGUAGE_INVALIDE')).isAlpha();
        }

        req.getValidationResult().then(
            function (result) {
                if (!result.isEmpty()) {
                    result.useFirstErrorOnly();
                    // console.log('There have been validation errors: ' + util.inspect(result.array()));
                    let _e = result.array({onlyFirstError: true})[0];
                    let _param = _e.param ? '.' + (_e.param).toUpperCase() : '';
                    next(apiErrorHelper.buildError(
                        400,
                        'API_PROFILE_VALIDATION_ERRORS.' + _param, 
                        'Invalid param.',
                        req.__('API_PROFILE_VALIDATION_ERRORS'),
                        [], 
                        {success: false})
                    );
                    
                } else {
                    userHelper.updateProfileLegacy(authHelper.getAuthenticatedUser(req), req.body).then(
                        function (userProfile) {
                            res.cookie(config.i18n.cookie_name, userProfile.language, {
                                maxAge: config.i18n.cookie_duration,
                                httpOnly: true
                            });
                            res.json({success: true, msg: req.__('API_PROFILE_SUCCESS')}); // FIXME standard message
                        },
                        function (err) {
                            if (err.message === userHelper.EXCEPTIONS.MISSING_FIELDS) {
                                next(apiErrorHelper.buildError(400,
                                        'API_SIGNUP_MISSING_FIELDS', 
                                        'Missing required fields.', 
                                        req.__('API_SIGNUP_MISSING_FIELDS'),
                                        [],
                                        {
                                            missingFields: err.data.missingFields
                                        }
                                    )
                                );
                            } else {
                                next(apiErrorHelper.buildError(
                                        500, 
                                        'INTERNAL_SERVER_ERROR.API_PROFILE_FAIL', 
                                        'Internal server error. Profile api failure.',  
                                        req.__('API_PROFILE_FAIL'), 
                                        [], 
                                        {success: false}
                                        )
                                    );
                            }
                        }
                    );
                }
            }
        );
    });


    var requiredConfigQueryPath = '/api/local/profile/required-config';
    app.options(requiredConfigQueryPath, cors);
    app.get(
        requiredConfigQueryPath,
        cors,
        function (req, res) {
            var fields = userHelper.getRequiredFields();
            var asObject = !req.query.hasOwnProperty('array');
            var providers = [];
            for (var idp in config.identity_providers) {
                if (config.identity_providers[idp].enabled) {
                    providers.push(idp);
                }
            }
            if (asObject) {
                return res.status(200).json({fields: fields, providers: providers});
            } else {
                var list = [];
                for (var key in fields) {
                    if (fields.hasOwnProperty(key) && fields[key]) {
                        list.push(key);
                    }
                }
                return res.status(200).json(list);
            }
        }
    );
};

function returnProfileAsJson(user, res, req) {
    db.LocalLogin.findOne({where: {user_id: user.id}}).then(function (localLogin) {
        if (localLogin){
            var email = localLogin.login;
            res.json({
                success: true,
                user_profile: {
                    id: user.id,
                    firstname: user.firstname,
                    lastname: user.lastname,
                    gender: user.gender,
                    date_of_birth: user.date_of_birth ? parseInt(user.date_of_birth) : user.date_of_birth,
                    date_of_birth_ymd: user.date_of_birth_ymd,
                    language: user.language,
                    email: email,
                    display_name: user.getDisplayName(req.query.policy, email)
                }
            });
        } else {
            db.SocialLogin.findOne({where: {user_id: user.id}}).then(function(socialLogin) {
                var email = socialLogin.email;
                res.json({
                    success: true,
                    user_profile: {
                        id: user.id,
                        firstname: user.firstname,
                        lastname: user.lastname,
                        gender: user.gender,
                        date_of_birth: user.date_of_birth ? parseInt(user.date_of_birth) : user.date_of_birth,
                        date_of_birth_ymd: user.date_of_birth_ymd,
                        language: user.language,
                        email: email,
                        display_name: user.getDisplayName(req.query.policy, email)
                    }
                });
            });
        }
    });
}


// Get the user for a given CPA token. Due to the fact that it is more "get user"
// than "authenticate" it has been moved here from auth-helper.
function getCpaAuthedUser(req) {
    return new Promise(function (resolve, reject) {
        var cpaToken = req.header('Authorization').replace('Bearer ', '');
        if (!cpaToken) {
            logger.warn("Access to CPA profile without cpa token");
            reject({"Error": "No token given: " + cpaToken});
        } else {
            db.AccessToken.findOne({where: {token: cpaToken}, include: [db.User]})
                .then(function (accessToken) {
                    if (!accessToken) {
                        logger.warn("Access to CPA profile without resolvable token", cpaToken);
                        reject({"Error": "No valid token given"});
                    } else {
                        if (accessToken.User) {
                            resolve(accessToken.User);
                        }
                        resolve();
                    }
                }, function (err) {
                    logger.error("Something spooky went wrong resolving CPA to user profile", err);
                    reject();
                });
        }
    });
}
