"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');


//---------------
// oAuth calls
function oAuthLogin(httpContext, done) {
    requestHelper.sendRequest(httpContext, '/oauth2/token', {
        method: 'post',
        data: {
            grant_type: 'password',
            username: initData.USER_1.email,
            password: initData.USER_1.password,
            client_id: initData.OAUTH_CLIENT_1.client_id,
            client_secret: initData.OAUTH_CLIENT_1.client_secret
        }
    }, function () {
        httpContext.token = httpContext.res.body.access_token;
        done();
    });
}


//---------------
// cookie calls
function cookieSignupWithProfile(httpContext, email, password, profileData, redirect, code, done) {
    var data = {
        email: email,
        password: password,
        'g-recaptcha-response': 'a dummy recaptcha response'
    };
    data = Object.assign(data, profileData);


    var uri = '/api/v2/session/signup';
    if (redirect) {
        uri += "?redirect=" + redirect;
        if (code) {
            uri += "&withcode=true";
        }
    }
    requestHelper.sendRequest(httpContext, uri, {
        method: 'post',
        type: 'form',
        data: data
    }, done);
}

function cookieSignup(httpContext, email, password, redirect, code, done) {
    cookieSignupWithProfile(httpContext, email, password, null, redirect, code, done);
}

function cookieLogin(httpContext, done) {
    cookieLoginWithRedirectOption(httpContext, null, null, done);
}

function cookieLoginWithCustomCrendentials(httpContext, email, password, done) {
    cookieLoginWithOptions(httpContext, email, password, null, null, done);
}

function cookieLoginWithRedirectOption(httpContext, redirect, code, done) {
    cookieLoginWithOptions(httpContext, initData.USER_1.email, initData.USER_1.password, redirect, code, done)
}

function cookieLoginWithOptions(httpContext, email, password, redirect, code, done) {
    var uri = '/api/v2/session/login';
    if (redirect) {
        uri += "?redirect=" + encodeURIComponent(redirect);
        if (code) {
            uri += "&withcode=true";
        }
    }
    requestHelper.sendRequest(httpContext, uri, {
            method: 'post',
            data: {
                email: email,
                password: password,
            }
        },
        done
    );
}

function cookieLogout(httpContext, done) {
    requestHelper.sendRequest(httpContext, '/api/v2/session/logout', {
        method: 'delete',
        cookie: httpContext.cookie
    }, done);
}


//---------------
// jwt calls

function jwtSignup(context, email, password, redirect, code, done) {

    var uri = '/api/v2/jwt/signup';
    if (redirect) {
        uri += "?redirect=" + redirect;
        if (code) {
            uri += '&withcode=true'
        }
    }
    requestHelper.sendRequest(context, uri, {
        method: 'post',
        data: {
            email: email,
            password: password,
            'g-recaptcha-response': 'a dummy recaptcha response'
        }
    }, function () {
        if (redirect) {
            const TOKEN_QUERY_STRING = '?token=';
            const LOCATION_HEADER = context.res.header.location;
            context.token = LOCATION_HEADER.substring(LOCATION_HEADER.indexOf(TOKEN_QUERY_STRING) + TOKEN_QUERY_STRING.length);
        } else {
            context.token = context.res.body.token.substring(4); //Remove "JWT " prefix
        }
        done();
    });
}

//---------------
// short cuts

function oAuth_authenticate() {
    return function(done) {
        let ctx = this;
        oAuthLogin(ctx, function() {
            ctx.accessToken = ctx.res.body.access_token;
            done();
        });
    };
}

function session_authenticate() {
    return function(done) {
        let ctx = this;
        cookieLogin(ctx, function() {
            ctx.cookie = ctx.res.headers['set-cookie'];
            done();
        });
    };
}

function jwt_authenticate(context, done) {
    requestHelper.sendRequest(context, '/api/v2/jwt/login', {
        method: 'post',
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
    cookieLoginWithRedirectOption: cookieLoginWithRedirectOption,
    cookieLoginWithCustomCrendentials: cookieLoginWithCustomCrendentials,
    cookieLogout: cookieLogout,
    cookieSignup: cookieSignup,
    cookieSignupWithProfile: cookieSignupWithProfile,
    jwt_authenticate: jwt_authenticate,
    jwtSignup: jwtSignup,
    oAuth_authenticate:oAuth_authenticate,
    session_authenticate:session_authenticate
};