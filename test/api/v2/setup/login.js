"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');


//---------------
// oAuth calls
function oAuthLogin(context, done) {
    requestHelper.sendRequest(context, '/oauth2/token', {
        method: 'post',
        data: {
            grant_type: 'password',
            username: initData.USER_1.email,
            password: initData.USER_1.password,
            client_id: initData.OAUTH_CLIENT_1.client_id,
            client_secret: initData.OAUTH_CLIENT_1.client_secret
        }
    }, function () {
        context.token = context.res.body.access_token;
        done();
    });
}


//---------------
// cookie calls

function cookieLogin(httpContext, done) {
    requestHelper.loginCustom(initData.USER_1.email, initData.USER_1.password, httpContext, function () {
        context.cookie = httpContext.cookie;
        done();
    });
}

function cookieLogout(httpContext, done) {
    requestHelper.sendRequest(httpContext, '/api/v2/session/logout', {
        method: 'delete',
        cookie: httpContext.cookie
    }, done);
}


//---------------
// jwt calls

function jwtLogin(context, done) {
    requestHelper.sendRequest(context, '/api/local/authenticate/jwt', {
        method: 'post',
        type: 'form',
        data: {
            email: initData.USER_1.email,
            password: initData.USER_1.password
        }
    }, function () {
        context.token = context.res.body.token.substring(4, context.res.body.token.size);
        done();
    });
}


module.exports = {
    oAuthLogin: oAuthLogin,
    cookieLogin: cookieLogin,
    cookieLogout: cookieLogout,
    jwtLogin: jwtLogin
};