"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var db = require('../../../../models/index');
var login = require('../setup/login');

describe('API-V2 LOGIN', function () {
    before(initData.resetDatabase);
    context('disconnect', function () {
        context('with valid session', function () {
            var ctx = this;

            before(function (done) {
                login.cookieLogin(ctx, done);
            });

            before(function (done) {
                login.cookieLogout(ctx, done);
            });

            it('should return a success', function () {
                expect(ctx.res.statusCode).equal(204);
            });
        });

        context('without session', function () {
            var ctx = this;

            before(function (done) {
                login.cookieLogout(ctx, done);
            });

            it('should return a success', function () {
                expect(ctx.res.statusCode).equal(401);
            });
        });

        context('when already disconnected', function () {
            var ctx = this;
            before(function (done) {
                login.cookieLogin(ctx, done);
            });

            before(function (done) {
                login.cookieLogout(ctx, done);
            });


            before(function (done) {
                login.cookieLogout(ctx, done);
            });

            it('should return a success', function () {
                expect(ctx.res.statusCode).equal(401);
            });
        });
    });

});





