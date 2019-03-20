'use strict';

const 
    initData = require('../setup/init-data'),
    jwt = require('jwt-simple'),
    login = require('../setup/login'),
    requestHelper = require('../../../request-helper');

describe('log in and check JWT', () => {

    before(initData.resetDatabase);
    
    context('log in', function () {
        var ctx = this;
        var clearJwt;
        before(function (done) {
            login.cookieLogin(ctx, done);
        });
        before(function (done) {
            requestHelper.sendRequest(ctx, '/api/v2/session/jwt', {cookie: ctx.cookie}, done);
        });
        before(() => {
            clearJwt = jwt.decode(ctx.res.body.token.substring("JWT ".length), null, true);
        });
        it('should return a success', () => {
            expect(ctx.res.body.token.indexOf("JWT ")).equal(0);
            expect(clearJwt.id).to.equal(initData.USER_1.id);
            expect(clearJwt.public_uid).to.equal(initData.USER_1_PROFILE.public_uid);
            expect(clearJwt.LocalLogin.login).to.equal(initData.USER_1.email);
        });
    });
});