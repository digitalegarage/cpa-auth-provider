"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var db = require('../../../../models');


describe('API-V2 user DELETE', function () {

    context('with good credential', function () {
        var ctx = this;

        before(initData.resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(ctx, "/api/v2/public/user", {
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
            requestHelper.sendRequest(ctx, "/api/v2/public/user", {
                    method: 'delete',
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






