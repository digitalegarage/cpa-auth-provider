'use strict';

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var nock = require('nock');
var config = require('../../../../config');

const VALID_FB_CODE = 42;
const REDIRECT_URI = 'https://localhost.ebu.io/unexistingurl';
const VALID_ACCESS_TOKEN = 'AccessTokenA';
const EMAIL = 'someone@gmail.com';
const USER_PROFILE = {
    first_name: 'Hans',
    last_name: 'Wurst',
    gender: 'male',
    birthday: '08/31/1978',
    birthday_ts: 273369600000,
};

describe('API-V2 Facebook for AJAX', function() {

    beforeEach(initData.resetEmptyDatabase);

    before(function() {
        mockFBForOneCallSequence();
    });

    after(function() {
        nock.cleanAll();
    });

    context('Code', function() {

        context('when missing body data', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/code', {
                    method: 'post',
                    data: {},
                }, done);
            });

            it('should return a 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
                expect(ctx.res.body.error);
                expect(ctx.res.body.error).to.equal('missing code and/or redirect_uri in request body');
            });

        });

        context('with valid FB code', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/code', {
                    method: 'post',
                    data: {
                        redirect_uri: REDIRECT_URI,
                        code: VALID_FB_CODE,
                    },
                }, done);
            });

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/session/user/profile', {
                    cookie: ctx.cookie,
                }, done);
            });

            it('user should be logged', function() {
                expect(ctx.res.statusCode).to.equal(200);
            });

        });

    });

    context('Token', function() {
        context('when missing token', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/token', {
                    method: 'post',
                    data: {},
                }, done);
            });

            it('should return a 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
                expect(ctx.res.body.error);
                expect(ctx.res.body.error).to.equal('missing token in request body');
            });

        });


        context('with valid FB token', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/token', {
                    method: 'post',
                    data: {
                        token: VALID_ACCESS_TOKEN,
                    },
                }, done);
            });

            before(function(done) {


                requestHelper.sendRequest(ctx, '/api/v2/session/user/profile', {
                    cookie: ctx.cookie,
                }, done);
            });

            it('user should be logged', function() {
                expect(ctx.res.statusCode).to.equal(200);
            });

        });

    });
});

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






