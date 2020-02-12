"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var login = require('../setup/login');
var config = require('../../../../config');



const NEW_DAB = "1989-11-09";
const NEW_FIRSTNAME = 'new firstname';
const NEW_LASTNAME = 'new lastname';
const NEW_GENDER = 'female';


describe('API-V2 profile', function () {

    context('GET : /api/v2/<security>/user/profile ', function () {
        before(initData.resetDatabase);
        context('using http basic auth', function() {
            var ctx = this;

            before(function(done) {
                httpBasicGetProfile(ctx,done);
            });

            it('should return a success', function() {
                expectGetPermissionEnrichedProfile(ctx);
            });
        });

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

        context('updating null-DOB using jwt', function () {
            var ctx = this;
            before(function (done) {
                login.jwtLogin(ctx, done);
            });
            before(function (done) {
                jwtUpdateNullDOB(ctx, done);
            });
            before(function (done) {
                jwtGetProfile(ctx, done);
            });
            it('should return a success', function () {
                expectNullDOB(ctx);
            });
        });

        context('updating valid DOB using jwt', function () {
            var ctx = this;
            before(function (done) {
                login.jwtLogin(ctx, done);
            });
            before(function (done) {
                jwtUpdateValidDOB(ctx, done);
            });
            before(function (done) {
                jwtGetProfile(ctx, done);
            });
            it('should return a success', function () {
                expectValidDOB(ctx);
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

    context('GET : /api/v2/all/nameByUid', function () {
        var preState;
        before(initData.resetDatabase);
        before(function() {
            preState = config.allow_name_access_by_puid;
            config.allow_name_access_by_puid = true;
        });
        after(function() {
            config.allow_name_access_by_puid = preState;
        });

        context('providing an invalid uuid', function() {
            var ctx = this;
            ctx.uuidToCall = '110';
            before(function(done) {
                getNameByUid(ctx,done);
            });
            it('should return an error', function(done) {
                expect(ctx.res.statusCode).to.equal(400);
                expect(JSON.parse(ctx.res.text).error.code).to.equal('BAD_REQUEST_INVALID_UUIDV4');
                done();
            });
        });
        context('providing a valid and used uuid', function(done) {
            var ctx = this;
            ctx.uuidToCall = '2b61aade-f9b5-47c3-8b5b-b9f4545ec9f9';
            before(function(done) {
                getNameByUid(ctx,done);
            });
            it('should return the name object', function(done) {
                expect(ctx.res.body.firstname).to.equal("John");
                expect(ctx.res.body.lastname).to.equal("Doe");
                done();
            });
        });
        context('providing a valid and unused uuid', function(done) {
            var ctx = this;
            ctx.uuidToCall = 'e2feaa99-f7dd-4e4c-a326-1bab74a25419';
            before(function(done) {
                getNameByUid(ctx,done);
            });
            it('should return an error', function(done) {

                expect(ctx.res.statusCode).to.equal(404);
                expect(JSON.parse(ctx.res.text).error.code).to.equal('USER_WITH_UUID_NOT_FOUND');
                done();
            });
        });
    });
    context('GET : /api/v2/all/nameByUid', function() {
        var preState;
        before(function() {
            initData.resetDatabase;
            preState = config.allow_name_access_by_puid;
            config.allow_name_access_by_puid = false;
        });
        after(function() {
            config.allow_name_access_by_puid = preState;
        });

        context('access to endpoint is denied by config', function(done) {
            config.allow_name_access_by_puid = false;
            var ctx = this;
            ctx.uuidToCall = '2b61aade-f9b5-47c3-8b5b-b9f4545ec9f9';
            before(function(done) {
                getNameByUid(ctx,done);
            });
            it('should return an error', function(done) {
                expect(ctx.res.statusCode).to.equal(409);
                expect(JSON.parse(ctx.res.text).error.code).to.equal('SERVICE_DISABLED_BY_CONFIGURATION');
                done();
            });
        });
    });
});

//---------------
// oAuth calls

function oAuthGetProfile(context, done) {
    requestHelper.sendRequest(
        context,
        "/api/v2/oauth/user/profile",
        {
            accessToken: context.token
        },
        done
    );
}

function oAuthUpdateProfile(context, done) {
    requestHelper.sendRequest(context, "/api/v2/oauth/user/profile", {
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

function jwtUpdateNullDOB(context,done) {
    requestHelper.sendRequest(context, "/api/v2/jwt/user/profile", {
        method: 'put',
        accessToken: context.token,
        data: {
            date_of_birth: ''
        }
    }, done);
}

function jwtUpdateValidDOB(context,done) {
    requestHelper.sendRequest(context, "/api/v2/jwt/user/profile", {
        method: 'put',
        accessToken: context.token,
        data: {
            date_of_birth: NEW_DAB
        }
    }, done);
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
// http basic auth calls
function httpBasicGetProfile(context,done) {
    requestHelper.sendRequest(context, "/api/v2/basicauth/user", {
        method: 'get',
        basicAuth: {
            login: initData.USER_1.email,
            password: initData.USER_1.password
        }
    }, done);
}

//---------------
// http name lookup call
function getNameByUid(context,done) {
    context.log = "Calling " + context.uuidToCall;
    requestHelper.sendRequest(context, "/api/v2/all/nameByUid/" + context.uuidToCall, {
        method: 'get'
    }, done);
}

//---------------
// expected results

function expectGetPermissionEnrichedProfile(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.id).not.equal(undefined);
    expect(context.res.body.permission_id).not.equal(undefined);
    expect(context.res.body.firstname).equal(initData.USER_1_PROFILE.firstname);
    expect(context.res.body.lastname).equal(initData.USER_1_PROFILE.lastname);
    expect(context.res.body.display_name).equal(initData.USER_1_PROFILE.firstname + " " + initData.USER_1_PROFILE.lastname);
    expect(context.res.body.gender).equal(initData.USER_1_PROFILE.gender);
    expect(context.res.body.public_uid).equal(initData.USER_1_PROFILE.public_uid);
}

function expectGetInitialProfile(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.id);
    expect(context.res.body.user.email).equals(initData.USER_1.email);
    expect(!context.res.body.user.email_verified);
    expect(context.res.body.user.display_name).equal(initData.USER_1_PROFILE.firstname + " " + initData.USER_1_PROFILE.lastname);
    expect(context.res.body.user.firstname).equal(initData.USER_1_PROFILE.firstname);
    expect(context.res.body.user.lastname).equal(initData.USER_1_PROFILE.lastname);
    expect(context.res.body.user.gender).equal(initData.USER_1_PROFILE.gender);
    expect(context.res.body.user.date_of_birth).equal(initData.USER_1_DAB_STR);
    expect(context.res.body.user.public_uid).equal(initData.USER_1_PROFILE.public_uid);
    expect(!context.res.body.user.language);
    expect(context.res.body.user.social_emails);
    expect(context.res.body.user.social_emails).to.be.empty;
    expect(context.res.body.user.login).equal(initData.USER_1.email);
    expect(context.res.body.user.has_password);
    expect(!context.res.body.user.has_facebook_login);
    expect(!context.res.body.user.has_google_login);
    expect(!context.res.body.user.has_social_login);
    expect(context.res.body.user.has_local_login);
}


function expectedGetUpdatedProfile(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.firstname).equal(NEW_FIRSTNAME);
    expect(context.res.body.user.lastname).equal(NEW_LASTNAME);
    expect(context.res.body.user.display_name).equal(NEW_FIRSTNAME + " " + NEW_LASTNAME);
    expect(context.res.body.user.gender).equal(NEW_GENDER);
    expect(context.res.body.user.date_of_birth).equal(NEW_DAB);
    expect(context.res.body.user.public_uid).equal(initData.USER_1_PROFILE.public_uid);
}

function expectNullDOB(context) {
    expect(context.res.statusCode).equal(200);
    expect(context.res.body.user.date_of_birth).to.be.null;
    expect(context.res.body.user.date_of_birth_ymd).to.be.undefined;
}

function expectValidDOB(context) {
    expect(context.res.statusCode).to.equal(200);
    expect(context.res.body.user.date_of_birth).to.equal(NEW_DAB);
}