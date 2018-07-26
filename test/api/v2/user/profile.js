"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');


const newDab = 1234567890;
const newFirstname = 'new firstname';
const newLastname = 'new lastname';
const newGender = 'female';


describe('API-V2 profile', function () {

    context('GET : /api/v2/oauth2/profile ', function () {
        before(initData.resetDatabase);

        context('using oauth token', function () {
            var httpContext = this;

            before(function (done) {
                oAuthLogin(httpContext, done);
            });

            before(function (done) {
                oAuthGetProfile(httpContext, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(httpContext);
            });
        });

        context('using cookie', function () {
            var httpContext = this;

            before(function (done) {
                cookieLogin(httpContext, done);
            });

            before(function (done) {
                cookieGetProfile(httpContext, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(httpContext);
            });
        });
    });


    context('PUT : /api/v2/oauth2/profile', function () {

        before(initData.resetDatabase);

        context('using oauth token', function () {
            var httpContext = this;

            before(function (done) {
                oAuthLogin(httpContext, done);
            });
            before(function (done) {
                oAuthUpdateProfile(httpContext, newFirstname, newLastname, newGender, newDab, done);
            });

            before(function (done) {
                oAuthGetProfile(httpContext, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(httpContext, newFirstname, newLastname, newGender, newDab);
            });
        });


        context('using cookie', function () {
            var httpContext = this;

            before(function (done) {
                cookieLogin(httpContext, done);
            });

            before(function (done) {
                cookieUpdateProfile(httpContext, newFirstname, newLastname, newGender, newDab, done);
            });

            before(function (done) {
                cookieGetProfile(httpContext, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(httpContext, newFirstname, newLastname, newGender, newDab);
            });
        });


    });


});

//---------------
// oAuth calls
function oAuthLogin(context, done) {
    requestHelper.sendRequest(context, '/oauth2/token', {
        method: 'post',
        type: 'form',
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

function oAuthGetProfile(context, done) {
    requestHelper.sendRequest(
        context,
        "/api/v2/oauth2/profile",
        {
            accessToken: context.token
        },
        done
    );
}

function oAuthUpdateProfile(context, newFirstname, newLastname, newGender, newDab, done) {
    requestHelper.sendRequest(context, "/api/v2/oauth2/profile", {
            method: 'put',
            accessToken: context.token,
            data: {
                firstname: newFirstname,
                lastname: newLastname,
                gender: newGender,
                date_of_birth: newDab,
            }
        },
        done
    );
}

//---------------
// cookie calls


function cookieLogin(httpContext, done) {
    requestHelper.loginCustom(initData.USER_1.email, initData.USER_1.password, httpContext, function () {
        context.cookie = httpContext.cookie;
        done();
    });
}

function cookieGetProfile(httpContext, done) {
    requestHelper.sendRequest(httpContext, '/api/v2/session/profile', {
        method: 'get',
        cookie: httpContext.cookie
    }, done);
}


function cookieUpdateProfile(context, newFirstname, newLastname, newGender, newDab, done) {
    requestHelper.sendRequest(context, "/api/v2/session/profile", {
            method: 'put',
            cookie: context.cookie,
            data: {
                firstname: newFirstname,
                lastname: newLastname,
                gender: newGender,
                date_of_birth: newDab,
            }
        },
        done
    );
}

//---------------
// expected results

function expectGetInitialProfile(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.firstname).equal(initData.USER_1_PROFILE.firstname);
    expect(context.res.body.user.lastname).equal(initData.USER_1_PROFILE.lastname);
    expect(context.res.body.user.gender).equal(initData.USER_1_PROFILE.gender);
    expect(context.res.body.user.date_of_birth).equal(initData.USER_1_PROFILE.date_of_birth);
    expect(context.res.body.user.date_of_birth_ymd).equal(initData.USER_1_DAB_STR);
}

function expectedGetUpdatedProfile(context, newFirstname, newLastname, newGender, newDab) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.firstname).equal(newFirstname);
    expect(context.res.body.user.lastname).equal(newLastname);
    expect(context.res.body.user.gender).equal(newGender);
    expect(context.res.body.user.date_of_birth).equal(newDab);
}





