"use strict";

var passport = require('passport');
var afterLoginHelper = require('../../../../lib/afterlogin-helper');
var cors = require('../../../../lib/cors');
var config = require('../../../../config');
var logger = require('../../../../lib/logger');
var requestHelper = require('../../../../lib/request-helper');
var LocalStrategy = require('passport-local').Strategy;
var authLocalHelper = require('../../../../lib/auth-local-helper');
var limiterHelper = require('../../../../lib/limiter-helper');
var authHelper = require('../../../../lib/auth-helper');
var afterLogoutHelper = require('../../../../lib/afterlogout-helper');

const SESSION_LOGIN_PATH = '/api/v2/session/cookie';

function getToken(res, token, req) {
// Hack to retrieve authentication cookie in headers
    let headers = res.getHeader("set-cookie");
    if (!Array.isArray(headers)) {
        var tmp = headers;
        headers = [];
        if (tmp) {
            headers.push(tmp);
        }
    }

    for (var header in headers) {

        if (headers[header] && headers[header].indexOf(config.auth_session_cookie.name) == 0) {
            var attributes = headers[header].split(';');
            for (var attribute in attributes) {
                if (attributes[attribute].indexOf(config.auth_session_cookie.name) == 0) {
                    token = attributes[attribute].substring(config.auth_session_cookie.name.length + 1); // +1 for equal char
                    break;
                }
            }
            break;
        }
    }

    // server doesn't set cookie (cookie is in the request). => respond with request one
    if (!token) {
        token = req.cookies[config.auth_session_cookie.name];
    }
    return token;
}


var localStrategyConf = {
    // by default, local strategy uses username and password, we will override with email
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true // allows us to pass back the entire request to the callback
};

const LOCAL_REDIRECT_STRATEGY = 'local-redirect';
const LOCAL_REDIRECT_SIGNUP_STRATEGY = 'local-signup-redirect';


passport.use(LOCAL_REDIRECT_STRATEGY, new LocalStrategy(localStrategyConf, authLocalHelper.localStrategyCallback));

passport.use(LOCAL_REDIRECT_SIGNUP_STRATEGY, new LocalStrategy(localStrategyConf, authLocalHelper.localSignupStrategyCallback));


module.exports = function (app, options) {

    /**
     * @swagger
     * definitions:
     *   Credentials:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password"
     *   SignupData:
     *      type: "object"
     *      properties:
     *           email:
     *               type: "string"
     *               example: "someone@domain.org"
     *               description: "user email"
     *           password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password"
     *           confirm_password:
     *               type: "string"
     *               example: "myVeryStrongPassword"
     *               description: "user password confirm value"
     *           gender:
     *               type: "string"
     *               enum: [other, male, female]
     *               example: male
     *               description: user gender
     *           date_of_birth:
     *               type: "string"
     *               example: 31.08.1978
     *               description: "user date of birth"
     *   Token:
     *      type: "object"
     *      properties:
     *           token:
     *               type: "string"
     *               example: "s%3AhWMtLUjPHIUvc-nSw2Lr-2YLZf_bE4hy.GXWJQgyHtd1ad3DubqvYNMKsJQ2bHceDdIZN1oTfcEY"
     *               description: "user session cookie value"
     *
     *
     */


    /**
     * @swagger
     * /api/v2/session/login:
     *   post:
     *     description: login
     *     operationId: "sessionLogin"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "credentials"
     *            description: "user credential"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/Credentials"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *          - in: query
     *            name: "code"
     *            example: "true"
     *            schema:
     *              type: string
     *              description: if present a first redirect'd be request to /api/v2/session/cookie
     *     responses:
     *          "204":
     *            description: "login succeed"
     *          "302":
     *            description: "a redirect with token in body response"
     *            schema:
     *              $ref: '#/definitions/Token'
     */
    app.post('/api/v2/session/login', cors,
        passport.authenticate(LOCAL_REDIRECT_STRATEGY, {session: true}),
        function (req, res) {

            afterLoginHelper.afterLogin(req.user, req.body.email || req.query.email, res);

            res.contentType('application/json');
            if (req.query.redirect) {
                if (req.query.code) {
                    res.setHeader('Location', requestHelper.getPath(SESSION_LOGIN_PATH + '?redirect=' + req.query.redirect));
                } else {
                    res.setHeader('Location', req.query.redirect);
                }
                res.writeHead(302);

                var token = getToken(res, token, req);

                res.write('{"token": "' + token + '"}');
                res.end();

            } else {
                res.sendStatus(204);
            }
        }
    );

    /**
     * @swagger
     * /api/v2/session/logout:
     *   delete:
     *     description: disconnect
     *     operationId: "sessionDisconnect"
     *     responses:
     *          "204":
     *            description: "user disconnected"
     */
    app.delete('/api/v2/session/logout', cors, authHelper.ensureAuthenticated, function (req, res, next) {

        afterLogoutHelper.afterLogout(res);
        req.logout();
        req.session.destroy(function (err) {
            if (err) {
                return next(err);
            }
            return res.sendStatus(204);
        });
    });


    /**
     * @swagger
     * /api/v2/session/signup:
     *   post:
     *     description: signup
     *     operationId: "signup"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "signup data"
     *            description: "signup data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/SignupData"
     *          - in: query
     *            name: "redirect"
     *            example: "http://somedomain.org"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *          - in: query
     *            name: "code"
     *            example: "true"
     *            schema:
     *              type: string
     *              description: if present a first redirect'd be request to /api/v2/session/cookie
     *     responses:
     *          "204":
     *            description: "signup succeed"
     *          "302":
     *            description: "a redirect with token in body response"
     *            schema:
     *              $ref: '#/definitions/Token'
     */
    app.post('/api/v2/session/signup', limiterHelper.verify, function (req, res, next) {

        passport.authenticate(LOCAL_REDIRECT_SIGNUP_STRATEGY, function (err, user, info) {

            if (res.headersSent){
                return res.end();
            }

            if (err) {
                return next(err);
            }
            // Redirect if it fails
            if (!user) {
                return res.json({error: info}); //TODO when email is already taken response code is 200
            }
            req.logIn(user, function (err) {
                if (req.query.redirect) {
                    if (req.query.code) {
                        res.setHeader('Location', requestHelper.getPath(SESSION_LOGIN_PATH + '?redirect=' + req.query.redirect));
                    } else {
                        res.setHeader('Location', req.query.redirect);
                    }
                    res.writeHead(302);

                    var token = getToken(res, token, req);

                    res.write('{"token": "' + token + '"}');
                    res.end();

                } else {
                    res.sendStatus(204);
                }
            });
        })(req, res, next);
    });

    /**
     * @swagger
     * /api/v2/session/cookie:
     *   get:
     *     description: login
     *     operationId: "getSessionCookie"
     *     parameters:
     *          - in: query
     *            name: "redirect"
     *            schema:
     *              type: string
     *              description: The redirect url to send the code
     *     responses:
     *          "200":
     *            description: "current session cookie"
     *            schema:
     *              $ref: '#/definitions/Token'
     *          "302":
     *            description: "a redirect with token as a get query parameter"
     */
    app.get(SESSION_LOGIN_PATH, cors, function (req, res, next) {
        if (req.query.redirect) {
            const redirectUrl = req.query.redirect + '?token=' + encodeURIComponent(req.cookies[config.auth_session_cookie.name]);
            logger.debug("about to redirect client to  ", redirectUrl);
            res.setHeader('Location', redirectUrl);
            res.writeHead(302);
            res.end();
        } else {
            res.json({token: req.cookies[config.auth_session_cookie.name]});
        }
    });

};