"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var config = require('../../../../config');
var login = require('../setup/login');
var userHelper = require('../../../../lib/user-helper');
var db = require('../../../../models');



describe('API-V2 Facebook for AJAX', function () {

    context('Code', function () {
        beforeEach(initData.resetEmptyDatabase);

            context('When missing body data', function () {
                var ctx = this;

                before(function (done) {
                    requestHelper.sendRequest(ctx, '/api/v2/auth/facebook/code', {
                        method: 'post',
                        data: {}
                    }, done);
                });

                it('should return a 400', function () {
                    expect(ctx.res.statusCode).to.equal(400);
                    expect(ctx.res.body.error);
                    expect(ctx.res.body.error).to.equal('missing code and/or redirect_uri in request body');
                });

            });

    });


})
;






