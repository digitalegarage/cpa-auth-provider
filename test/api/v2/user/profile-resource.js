"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var login = require('../setup/login');


const NEW_DAB = "1989-11-09";
const NEW_FIRSTNAME = 'new firstname';
const NEW_LASTNAME = 'new lastname';
const NEW_GENDER = 'female';


describe('API-V2 profile', function () {

    context('GET : /api/v2/<security>/user/profile ', function () {

        before(initData.resetDatabase);

        context('using oauth token', function () {
            var ctx = this;

            before(function (done) {
                login.oAuthLogin(ctx, done);
            });

            before(function (done) {
                oAuthGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(ctx);
            });
        });

        context('using session cookie', function () {
            var ctx = this;

            before(function (done) {
                login.cookieLogin(ctx, done);
            });

            before(function (done) {
                cookieGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(ctx);
            });
        });

        context('using JWT', function () {
            var ctx = this;

            before(function (done) {
                login.jwtLogin(ctx, done);
            });

            before(function (done) {
                jwtGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(ctx);
            });
        });

        context('using CPA', function () {
            var ctx = this;
            ctx.token = initData.USER_1_CPA_TOKEN;

            before(function (done) {
                cpaGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectGetInitialProfile(ctx);
            });
        });
    });


    context('PUT : /api/v2/<security>/user/profile', function () {

        before(initData.resetDatabase);

        context('using oauth token', function () {
            var ctx = this;

            before(function (done) {
                login.oAuthLogin(ctx, done);
            });
            before(function (done) {
                oAuthUpdateProfile(ctx, done);
            });

            before(function (done) {
                oAuthGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(ctx);
            });
        });

        context('using session cookie', function () {
            var ctx = this;

            before(function (done) {
                login.cookieLogin(ctx, done);
            });

            before(function (done) {
                cookieUpdateProfile(ctx, done);
            });

            before(function (done) {
                cookieGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(ctx);
            });
        });

        context('using jwt', function () {
            var ctx = this;

            before(function (done) {
                login.jwtLogin(ctx, done);
            });

            before(function (done) {
                jwtUpdateProfile(ctx, done);
            });

            before(function (done) {
                jwtGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(ctx);
            });
        });
        context('using CPA', function () {
            var ctx = this;
            ctx.token = initData.USER_1_CPA_TOKEN;

            before(function (done) {
                cpaUpdateProfile(ctx, done);
            });

            before(function (done) {
                cpaGetProfile(ctx, done);
            });

            it('should return a success', function () {
                expectedGetUpdatedProfile(ctx);
            });
        });
    });
});

//---------------
// oAuth calls

function oAuthGetProfile(context, done) {
    requestHelper.sendRequest(
        context,
        "/api/v2/oauth2/user/profile",
        {
            accessToken: context.token
        },
        done
    );
}

function oAuthUpdateProfile(context, done) {
    requestHelper.sendRequest(context, "/api/v2/oauth2/user/profile", {
            method: 'put',
            accessToken: context.token,
            data: {
                firstname: NEW_FIRSTNAME,
                lastname: NEW_LASTNAME,
                gender: NEW_GENDER,
                date_of_birth: NEW_DAB,
            }
        },
        done
    );
}

//---------------
// cookie calls

function cookieGetProfile(httpContext, done) {
    requestHelper.sendRequest(httpContext, '/api/v2/session/user/profile', {
        method: 'get',
        cookie: httpContext.cookie
    }, done);
}

function cookieUpdateProfile(context, done) {
    requestHelper.sendRequest(context, "/api/v2/session/user/profile", {
            method: 'put',
            cookie: context.cookie,
            data: {
                firstname: NEW_FIRSTNAME,
                lastname: NEW_LASTNAME,
                gender: NEW_GENDER,
                date_of_birth: NEW_DAB,
            }
        },
        done
    );
}

//---------------
// jwt calls

function jwtGetProfile(context, done) {
    requestHelper.sendRequest(context, '/api/v2/jwt/user/profile', {
        method: 'get',
        accessToken: context.token,
    }, done);
}


function jwtUpdateProfile(context, done) {
    requestHelper.sendRequest(context, "/api/v2/jwt/user/profile", {
            method: 'put',
            accessToken: context.token,
            data: {
                firstname: NEW_FIRSTNAME,
                lastname: NEW_LASTNAME,
                gender: NEW_GENDER,
                date_of_birth: NEW_DAB,
            }
        },
        done
    );
}

//---------------
// cpa calls

function cpaGetProfile(context, done) {
    requestHelper.sendRequest(context, '/api/v2/cpa/user/profile', {
        method: 'get',
        accessToken: context.token,
    }, done);
}


function cpaUpdateProfile(context, done) {
    requestHelper.sendRequest(context, "/api/v2/jwt/user/profile", {
            method: 'put',
            accessToken: context.token,
            data: {
                firstname: NEW_FIRSTNAME,
                lastname: NEW_LASTNAME,
                gender: NEW_GENDER,
                date_of_birth: NEW_DAB,
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
    expect(context.res.body.user.display_name).equal(initData.USER_1_PROFILE.firstname + " " + initData.USER_1_PROFILE.lastname);
    expect(context.res.body.user.gender).equal(initData.USER_1_PROFILE.gender);
    expect(context.res.body.user.date_of_birth).equal(initData.USER_1_DAB_STR);
}

function expectedGetUpdatedProfile(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.firstname).equal(NEW_FIRSTNAME);
    expect(context.res.body.user.lastname).equal(NEW_LASTNAME);
    expect(context.res.body.user.display_name).equal(NEW_FIRSTNAME + " " + NEW_LASTNAME);
    expect(context.res.body.user.gender).equal(NEW_GENDER);
    expect(context.res.body.user.date_of_birth).equal(NEW_DAB);
}





