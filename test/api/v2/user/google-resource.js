'use strict';

const requestHelper = require('../../../request-helper'),
      initData = require('../setup/init-data'),
      nock = require('nock'),
      googleHelper = require('../../../../lib/google-helper'),
      login = require('../setup/login');


const VALID_ACCESS_TOKEN = 'AccessTokenA';
const USER_PROFILE = {
    first_name: 'Hans',
    last_name: 'Wurst',
    gender: 'male',
    birthday: '08/31/1978',
    birthday_ts: 273369600000,
};

var GOOGLE_EMAIL = 'someone@gmail.com';
var GOOGLE_PROVIDER_UID = 'google:1234';
var GOOGLE_DISPLAY_NAME = 'Hans Wurst';

describe('API-V2 Google for AJAX', function() {

    beforeEach(initData.resetEmptyDatabase);

    before(function () {
        sinon.stub(googleHelper, "verifyGoogleIdToken").returns(
            mockVerifyGoogleIdToken()
        );
        sinon.stub(googleHelper, "getGoogleToken").returns(
            mockGetGoogleToken()
        );
    });

    after(function() {
        nock.cleanAll();
    });

    context('Token', function() {
        context('when missing token', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/token', {
                    method: 'post',
                    data: {},
                }, done);
            });

            it('should return a 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
                expect(ctx.res.body.error.code).to.equal('TOKEN_MISSING');
            });

        });


        context('with valid Google token', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/token', {
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

        context('when a not verified account already exists with this gmail account', function() {

            var ctx = this;

            before(function(done) {
                login.cookieSignup(ctx, GOOGLE_EMAIL, "ACrazyPasswordThatNo1wouldChallenge. Ever!", null, null, done);
            });

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/token?defaultLanguage=en', {
                    method: 'post',
                    data: {
                        token: VALID_ACCESS_TOKEN,
                    },
                }, done);
            });
           it('user should returns 412', function() {
               expect(ctx.res.statusCode).to.equal(412);
               expect(ctx.res.body.error.code).to.equal("AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL");
               expect(ctx.res.body.error.errors.length).to.equal(0);
            });
        });

    });

    context('Code', function() {

        context('when missing body data', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/code', {
                    method: 'post',
                    data: {},
                }, done);
            });

            it('should return a 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
                expect(ctx.res.body.error.code).to.equal('CODE_MISSING');
            });

        });

        context('with valid google code', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/code', {
                    method: 'post',
                    data: {
                        redirect_uri: 'http://localhost',
                        code: 'a_valid_code',
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
        context('when a not verified account already exists with this gmail account', function() {

            var ctx = this;

            before(function(done) {
                login.cookieSignup(ctx, GOOGLE_EMAIL, "ACrazyPasswordThatNo1wouldChallenge. Ever!", null, null, done);
            });

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/google/code?defaultLanguage=en', {
                    method: 'post',
                    data: {
                        redirect_uri: 'http://localhost',
                        code: 'a_valid_code',
                    },
                }, done);
            });
            it('user should returns 412', function() {
                expect(ctx.res.statusCode).to.equal(412);
                expect(ctx.res.body.error.code).to.equal("AN_UNVALIDATED_ACCOUNT_EXISTS_WITH_THAT_MAIL");
                expect(ctx.res.body.error.errors.length).to.equal(0);
            });
        });

    });

});

function mockVerifyGoogleIdToken() {
    return new Promise(function (resolve, reject) {
        resolve({
            provider_uid: GOOGLE_PROVIDER_UID,
            display_name: GOOGLE_DISPLAY_NAME,
            email: GOOGLE_EMAIL,
            givenName: USER_PROFILE.first_name,
            familyName: USER_PROFILE.last_name,
            gender: USER_PROFILE.gender,
            birthday: null
        });
    });
}



function mockGetGoogleToken() {
    return new Promise(function (resolve, reject) {
        resolve("a_valid_token");
    });
}





