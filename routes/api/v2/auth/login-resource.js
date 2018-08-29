"use strict";

var passport = require('passport');
var afterLoginHelper = require('../../../../lib/afterlogin-helper');
var cors = require('../../../../lib/cors');
var config = require('../../../../config');
var logger = require('../../../../lib/logger');


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
     *     responses:
     *          "200":
     *            description: "login succeed"
     */
    app.post('/api/v2/session/login', cors,
        passport.authenticate('local', {session: true}),
        function (req, res, next) {

            afterLoginHelper.afterLogin(req.user, req.body.email || req.query.email, res);

            res.contentType('application/json');
            res.writeHead(200);

            // Hack to retrieve authentication cookie in headers
            let headers = res.getHeader("set-cookie");
            var token;
            for (var header in headers) {
                logger.debug("parsing ", headers[header]);
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
        }
    );

};