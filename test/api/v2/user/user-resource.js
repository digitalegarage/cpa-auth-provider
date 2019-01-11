'use strict';

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var db = require('../../../../models/index');
var login = require('../setup/login');
var nock = require('nock');
var config = require('../../../../config');

const REDIRECT_URI = 'https://localhost.ebu.io/unexistingurl';
const VALID_FB_CODE = 42;
const VALID_ACCESS_TOKEN = 'AccessTokenA';
const EMAIL = 'someone@gmail.com';
const PASSWORD = 'azertyuiopazertyuiop';
const NEW_PASSWORD = 'azertyuiopazertyuiop2';
const USER_PROFILE = {
    first_name: 'Hans',
    last_name: 'Wurst',
    gender: 'male',
    birthday: '08/31/1978',
    birthday_ts: 273369600000,
};

describe('API-V2 JWT get user id', function() {
    context('with good JWT in header', function() {
        var ctx = this;

        before(initData.resetDatabase);

        before(function(done) {
            login.jwtLogin(ctx, done);
        });

        before(function(done) {
            jwtGeUserId(ctx, done);
        });

        it('should return success', function() {
            expect(ctx.res.statusCode).equal(200);
            expect(ctx.res.body.id).equal(initData.USER_1_ID);

        });

    });
    context('with bad JWT in header', function() {
        var ctx = this;

        before(initData.resetDatabase);

        before(function(done) {
            login.jwtLogin(ctx, done);
        });

        before(function(done) {
            ctx.token = 'bad header format';
            jwtGeUserId(ctx, done);
        });

        it('should return success 401', function() {
            expect(ctx.res.statusCode).equal(401);
            expect(ctx.res.text).equal('{"error":"Cannot parse JWT token"}');
        });

    });
    context('with no authorization header', function() {
        var ctx = this;

        before(initData.resetDatabase);

        before(function(done) {
            login.jwtLogin(ctx, done);
        });

        before(function(done) {
            ctx.token = null;
            jwtGeUserId(ctx, done);
        });

        it('should return 401', function() {
            expect(ctx.res.statusCode).equal(401);
            expect(ctx.res.text).equal('{"error":"missing header Authorization"}');
        });

    });
});

describe('API-V2 user DELETE', function() {

    context('with good credential', function() {
        var ctx = this;

        before(initData.resetDatabase);

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/basicauth/user', {
                    method: 'delete',
                    basicAuth: {
                        login: initData.USER_1.email,
                        password: initData.USER_1.password,
                    },
                },
                done,
            );
        });

        it('should return a success', function() {
            expect(ctx.res.statusCode).equal(204);
        });
    });

    context('with good credential', function() {
        var ctx = this;

        before(initData.resetDatabase);

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/basicauth/user', {
                    method: 'del',
                    basicAuth: {
                        login: initData.USER_1.email,
                        password: initData.USER_1.password,
                    },
                },
                done,
            );
        });

        before(function(done) {
            db.LocalLogin.findOne({where: {login: initData.USER_1.email}}).then(function(ll) {
                ctx.ll = ll;
                done();
            });
        });

        it('should drop the user', function() {
            expect(ctx.ll).to.be.null;
        });
    });

});

describe('API-V2 add local login', function() {

    before(function() {
        mockFBForOneCallSequence();
    });

    after(function() {
        nock.cleanAll();
    });

    var ctx = this;

    context('using session', function() {
        before(initData.resetDatabase);

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/token', {
                method: 'post',
                data: {
                    token: VALID_ACCESS_TOKEN,
                },
            }, done);
        });

        context('with incorrect data', function() {
            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/session/user/login/create', {
                    method: 'post',
                    cookie: ctx.cookie,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: 'different password',
                    },
                }, done);
            });

            it(' should be 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
            });
        });

        context('with correct data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/session/user/login/create', {
                    method: 'post',
                    cookie: ctx.cookie,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: PASSWORD,
                    },
                }, done);
            });
            context('response', function() {

                it(' should be 200', function() {
                    expect(ctx.res.statusCode).to.equal(200);
                });
            });
            context('User can login using new credentials', function() {

                before(function(done) {
                    loginWithNewLocalLogin(ctx, done);
                });

                it('user should be able to log', function() {
                    expect(ctx.res.statusCode).to.equal(204);
                });
            });
        });

    });
    context('using jwt', function() {
        before(initData.resetDatabase);

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/token', {
                method: 'post',
                data: {
                    token: VALID_ACCESS_TOKEN,
                },
            }, done);
        });

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/session/jwt', {
                method: 'get',
                cookie: ctx.cookie,
            }, function() {
                ctx.token = ctx.res.body.token.substring(4, ctx.res.body.token.size);
                done();
            });
        });

        context('with incorrect data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/jwt/user/login/create', {
                    method: 'post',
                    accessToken: ctx.token,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: 'different password',
                    },
                }, done);
            });

            it(' should be 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
            });
        });

        context('with correct data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/jwt/user/login/create', {
                    method: 'post',
                    accessToken: ctx.token,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: PASSWORD,
                    },
                }, done);
            });
            context('response', function() {

                it(' should be 200', function() {
                    expect(ctx.res.statusCode).to.equal(200);
                });
            });
            context('User can login using new credentials', function() {

                before(function(done) {
                    loginWithNewLocalLogin(ctx, done);
                });

                it('user should be able to log', function() {
                    expect(ctx.res.statusCode).to.equal(204);
                });
            });
        });

    });

    context('using CPA', function() {
        before(initData.resetDatabase);

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/token', {
                method: 'post',
                data: {
                    token: VALID_ACCESS_TOKEN,
                },
            }, done);
        });

        context('with incorrect data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/cpa/user/login/create', {
                    method: 'post',
                    accessToken: initData.USER_1_CPA_TOKEN,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: 'different password',
                    },
                }, done);
            });

            it(' should be 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
            });
        });

        context('with correct data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/cpa/user/login/create', {
                    method: 'post',
                    accessToken: initData.USER_1_CPA_TOKEN,
                    data: {
                        email: EMAIL,
                        password: PASSWORD,
                        confirm_password: PASSWORD,
                    },
                }, done);
            });
            context('response', function() {

                it(' should be 200', function() {
                    expect(ctx.res.statusCode).to.equal(200);
                });
            });
            context('User can login using new credentials', function() {

                before(function(done) {
                    loginWithNewLocalLogin(ctx, done);
                });

                it('user should be able to log', function() {
                    expect(ctx.res.statusCode).to.equal(204);
                });
            });
        });
    });

    context('using oAuth', function() {
        // there is no way to have a valid oAuth access token without a local login => no endpoint => no test

    });

});

describe('API-V2 change password', function() {

    let ctx = this;
    context('using any protocol', function() {
        before(initData.resetDatabase);

        context('with incorrect data', function() {
            context('(password are different)', function() {

                before(function(done) {

                    requestHelper.sendRequest(ctx, '/api/v2/all/user/password', {
                        method: 'post',
                        data: {
                            email: initData.USER_1.email,
                            previous_password: initData.USER_1.password,
                            new_password: NEW_PASSWORD,
                            confirm_password: 'different password',
                        },
                    }, done);
                });

                it(' should be 400', function() {
                    expect(ctx.res.statusCode).to.equal(400);
                });
            });
            context('(new password is weak)', function() {

                before(function(done) {

                    requestHelper.sendRequest(ctx, '/api/v2/all/user/password', {
                        method: 'post',
                        data: {
                            email: initData.USER_1.email,
                            previous_password: initData.USER_1.password,
                            new_password: "weak",
                            confirm_password: "weak",
                        },
                    }, done);
                });

                it(' should be 400', function() {
                    expect(ctx.res.statusCode).to.equal(400);
                });
            });
            context('(unexisting user)', function() {

                before(function(done) {

                    requestHelper.sendRequest(ctx, '/api/v2/all/user/password', {
                        method: 'post',
                        data: {
                            email: "unexistig@user.com",
                            previous_password: initData.USER_1.password,
                            new_password: NEW_PASSWORD,
                            confirm_password: NEW_PASSWORD,
                        },
                    }, done);
                });

                it(' should be 401', function() {
                    expect(ctx.res.statusCode).to.equal(401);
                });
            });
        });

        context('with correct data', function() {

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/all/user/password', {
                    method: 'post',
                    data: {
                        email: initData.USER_1.email,
                        previous_password: initData.USER_1.password,
                        new_password: NEW_PASSWORD,
                        confirm_password: NEW_PASSWORD,
                    },
                }, done);
            });
            context('response', function() {

                it(' should be 200', function() {
                    console.log("ctx.res: " , ctx.res);
                    expect(ctx.res.statusCode).to.equal(200);
                });
            });
            context('User can login using new credentials', function() {

                before(function(done) {
                    requestHelper.sendRequest(ctx, '/api/v2/session/login', {
                            method: 'post',
                            data: {
                                email: initData.USER_1.email,
                                password: NEW_PASSWORD,
                            },
                        },
                        done,
                    );
                });

                it('user should be able to log', function() {
                    expect(ctx.res.statusCode).to.equal(204);
                });
            });
        });

    });

});

///////////////////:
// Utils

function jwtGeUserId(context, done) {
    requestHelper.sendRequest(context, '/api/v2/jwt/user/id', {
        method: 'get',
        accessToken: context.token,
    }, done);
}

function mockFBForOneCallSequence() {

    nock('https://graph.facebook.com').persist().get('/v3.2/oauth/access_token?' +
        'redirect_uri=' + REDIRECT_URI +
        '&client_id=' + config.identity_providers.facebook.client_id +
        '&client_secret=' + config.identity_providers.facebook.client_secret +
        '&code=' + VALID_FB_CODE).reply(200, {access_token: VALID_ACCESS_TOKEN, token_type: 'Bearer', expires_in: 3600});

    nock('https://graph.facebook.com').persist().
    get(function(uri) { // Probably due to pipe encoding (%7C) matcher fail using 'https://graph.facebook.com/debug_token?input_token=AccessTokenA&access_token=abc%7C123'
        return uri.indexOf('/debug_token?input_token=' + VALID_ACCESS_TOKEN + '&access_token=' + config.identity_providers.facebook.client_id + '%7C' +
            config.identity_providers.facebook.client_secret) === 0;
    }).
    reply(200,
        {
            'data': {
                'app_id': '2162601360474008',
                'type': 'USER',
                'application': 'DemoLoginAjaxFlow',
                'data_access_expires_at': 1551954866,
                'expires_at': 1549354047,
                'is_valid': true,
                'issued_at': 1544170047,
                'scopes': [
                    'public_profile',
                ],
                'user_id': '194104511537081',
            },
        });

    nock('https://graph.facebook.com').persist().
    get('/v3.2/me?' +
        'fields=id,name,email,first_name,last_name,gender' +
        '&access_token=' + VALID_ACCESS_TOKEN).
    reply(200, {
        id: 'fffaaa-123',
        name: 'Cool Name',
        email: EMAIL,
        first_name: USER_PROFILE.first_name,
        last_name: USER_PROFILE.last_name,
        gender: USER_PROFILE.gender,
        birthday: USER_PROFILE.birthday,
    });

}

function loginWithNewLocalLogin(ctx, done) {
    requestHelper.sendRequest(ctx, '/api/v2/session/login', {
            method: 'post',
            data: {
                email: EMAIL,
                password: PASSWORD,
            },
        },
        done,
    );
}