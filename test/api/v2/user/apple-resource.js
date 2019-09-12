'use strict';

const requestHelper = require('../../../request-helper'),
    initData = require('../setup/init-data'),
    appleHelper = require('../../../../lib/apple-helper');

const VALID_ACCESS_TOKEN = 'AccessTokenA';
const EMAIL = 'someone@gmail.com';

const db = require('../../../../models');

describe('API-V2 Google for AJAX', function() {

    beforeEach(initData.resetEmptyDatabase);

    before(function() {
        sinon.stub(appleHelper, 'verifyIdToken').returns(
            new Promise(function(resolve, reject) {
                resolve({
                    sub: '123', email:
                    EMAIL
                });
            })
        );
    });

    after(function() {
        appleHelper.verifyIdToken.restore();
    });

    context('Token', function() {
        context('when missing token', function() {
            var ctx = this;

            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/apple/token', {
                    method: 'post',
                    data: {}
                }, done);
            });

            it('should return a 400', function() {
                expect(ctx.res.statusCode).to.equal(400);
                expect(ctx.res.body.error);
                expect(ctx.res.body.error.code).to.equal('TOKEN_MISSING');
            });

        });

        context('with valid Apple token', function() {
            var ctx = this;



            before(function(done) {
                requestHelper.sendRequest(ctx, '/api/v2/auth/apple/token', {
                    method: 'post',
                    data: {
                        token: VALID_ACCESS_TOKEN
                    }
                }, done);
            });

            before(function(done) {

                requestHelper.sendRequest(ctx, '/api/v2/session/user/profile', {
                    cookie: ctx.cookie
                }, done);
            });

            it('user should be logged', function() {
                expect(ctx.res.statusCode).to.equal(200);
            });

        });

    });
});

describe('Test delete social account by session', function() {
    beforeEach(initData.resetEmptyDatabase);

    before(function() {
        sinon.stub(appleHelper, 'verifyIdToken').returns(
            new Promise(function(resolve, reject) {
                resolve({
                    sub: '123', email:
                    EMAIL
                });
            })
        );
    });

    after(function() {
        appleHelper.verifyIdToken.restore();
    });

    context('when user doesn\'t have a local login', function() {
        var ctx = this;

        before(function(done) {
            db.User.count({}).then(function(count) {
                ctx.countBefore = count;
                done();
            });
        });

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/auth/apple/token', {
                method: 'post',
                data: {
                    token: VALID_ACCESS_TOKEN
                }
            }, done);
        });

        before(function(done) {
            requestHelper.sendRequest(ctx, '/api/v2/session/user', {method: 'delete', cookie: ctx.cookie}, done);
        });


        before(function(done) {
            db.User.count({}).then(function(count) {
                ctx.count = count;
                done();
            });
        });

        it('user should not be deleted', function() {
            expect(ctx.countBefore).to.equal(ctx.count);
        });

        it('should return a 204', function() {
            expect(ctx.res.statusCode).to.equal(204);
        });

    });

});





