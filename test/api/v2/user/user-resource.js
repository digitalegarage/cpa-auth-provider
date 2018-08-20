"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var db = require('../../../../models/index');
var login = require('../setup/login');

describe('API-V2 JWT get user id', function () {
    context('with good JWT in header', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            login.jwtLogin(ctx, done)
        });

        before(function (done) {
            jwtGeUserId(ctx, done);
        });

        it('should return success', function(){
            expect(ctx.res.statusCode).equal(200);
            expect(ctx.res.body.id).equal(initData.USER_1_ID);

        });

    });
    context('with bad JWT in header', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            login.jwtLogin(ctx, done)
        });

        before(function (done) {
            ctx.token = "bad header format";
            jwtGeUserId(ctx, done);
        });

        it('should return success 401', function(){
            expect(ctx.res.statusCode).equal(401);
            expect(ctx.res.text).equal('{"error":"Cannot parse JWT token"}');
        });

    });
    context('with no authorization header', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            login.jwtLogin(ctx, done)
        });

        before(function (done) {
            ctx.token = null;
            jwtGeUserId(ctx, done);
        });

        it('should return 401', function(){
            expect(ctx.res.statusCode).equal(401);
            expect(ctx.res.text).equal('{"error":"missing header Authorization"}');
        });

    });
});


describe('API-V2 user DELETE', function () {

    context('with good credential', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(ctx, "/api/v2/basicauth/user", {
                    method: 'delete',
                    basicAuth: {
                        login: initData.USER_1.email,
                        password: initData.USER_1.password
                    }
                },
                done
            );
        });

        it('should return a success', function () {
            expect(ctx.res.statusCode).equal(204);
        });
    });

    context('with good credential', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(ctx, "/api/v2/basicauth/user", {
                    method: 'del',
                    basicAuth: {
                        login: initData.USER_1.email,
                        password: initData.USER_1.password
                    }
                },
                done
            );
        });

        before(function (done) {
            db.LocalLogin.findOne({where: {login: initData.USER_1.email}}).then(function (ll) {
                ctx.ll = ll;
                done();
            });
        });

        it('should drop the user', function () {
            expect(ctx.ll).to.be.null;
        });
    });

});


function jwtGeUserId(context, done) {
    requestHelper.sendRequest(context, '/api/v2/jwt/user/id', {
        method: 'get',
        accessToken: context.token,
    }, done);
}






