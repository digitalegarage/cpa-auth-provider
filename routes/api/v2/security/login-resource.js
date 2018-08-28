"use strict";

var passport = require('passport');
var afterLoginHelper = require('../../../../lib/afterlogin-helper');
var cors = require('../../../../lib/cors');
var config = require('../../../../config');


module.exports = function (app, options) {
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

            res.write('{"token": "' + token + '"}');
            res.end();
        }
    );

};