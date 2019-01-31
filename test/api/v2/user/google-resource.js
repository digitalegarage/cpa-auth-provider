'use strict';

const requestHelper = require('../../../request-helper'),
      initData = require('../setup/init-data'),
      nock = require('nock'),
      googleHelper = require('../../../../lib/google-helper');


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
                expect(ctx.res.body.error);
                expect(ctx.res.body.error).to.equal('missing token in request body');
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





