"use strict";

var passport = require('passport');
var afterLoginHelper = require('../../../../lib/afterlogin-helper');
var cors = require('../../../../lib/cors');
var config = require('../../../../config');
var logger = require('../../../../lib/logger');
var requestHelper = require('../../../../lib/request-helper');

const SESSION_LOGIN_PATH = '/api/v2/session/cookie';

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
     *          "200":
     *            description: "login succeed"
     */
    app.post('/api/v2/session/login', cors,
        passport.authenticate('local', {session: true}),
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

                // Hack to retrieve authentication cookie in headers
                let headers = res.getHeader("set-cookie");
                if (! Array.isArray(headers)){
                    var tmp = headers;
                    headers = [];
                    headers.push(tmp);
                }

                var token;
                for (var header in headers) {

                    if (headers[header].indexOf(config.auth_session_cookie.name) == 0) {
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

                res.write('{"token": "' + token + '"}');
                res.end();

            } else {
                res.sendStatus(204);
            }
        }
    );

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
     *            schema:
     *              $ref: '#/definitions/Token'
     */
    app.get(SESSION_LOGIN_PATH, cors, function (req, res, next) {
        if (req.query.redirect) {
            const redirectUrl = req.query.redirect + '?token=' + req.cookies[config.auth_session_cookie.name];
            logger.debug("about to redirect client to  ", redirectUrl);
            res.setHeader('Location', redirectUrl);
            res.writeHead(302);
            res.end();
        } else {
            res.json({token: req.cookies[config.auth_session_cookie.name]});
        }
    });

};