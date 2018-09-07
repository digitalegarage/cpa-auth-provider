"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var config = require('../../../../config');
var login = require('../setup/login');

describe('API-V2 LOGIN', function () {
    before(initData.resetDatabase);

    context('login', function () {
        context('session', function () {
            context('with correct credentials', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLogin(ctx, done);
                });
                it('should return a success', function () {
                    expect(ctx.res.statusCode).equal(204);
                });
            });
            context('with bad credentials', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithCustomCrendentials(ctx, "wronglogin", "wrongpassword", done);
                });
                it('should return a success', function () {
                    expect(ctx.res.statusCode).equal(401);
                });
            });
            context('with redirects and no code', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithRedirectOption(ctx, 'http://somedomain.org', false, done);
                });
                it('should return a 302 at request location', function () {
                    expect(ctx.res.statusCode).equal(302);
                    expect(ctx.res.headers["location"]).equal('http://somedomain.org');
                });
            });
            context('with redirects and code', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithRedirectOption(ctx, 'http://somedomain.org', true, done);
                });
                it('should return a 302 redirect to /api/v2/session/cookie', function () {
                    expect(ctx.res.statusCode).equal(302);
                    expect(ctx.res.headers["location"]).equal('/ap/api/v2/session/cookie?redirect=http://somedomain.org');
                });
            });
        });
    });
    context('retrieve session token', function () {
        context('session', function () {
            context('with redirects and code', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithRedirectOption(ctx, 'http://somedomain.org', true, done);
                });
                before(function (done) {
                    requestHelper.sendRequest(ctx, '/api/v2/session/cookie?redirect=' + encodeURIComponent('http://somedomain.org'), {cookie: ctx.cookie}, done);
                });
                it('should return a 302 redirect to /api/v2/session/cookie', function () {
                    expect(ctx.res.statusCode).equal(302);
                    expect(ctx.res.headers["location"]).equal('http://somedomain.org?token=' + getCookieValue(ctx.cookie));
                });
            });
        });
    });

    context('logout', function () {
        context('session', function () {
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

});

function getCookieValue(cookieStr) {
    //cookie format: connect.sid=s%3A0Xf6JiMbGdO9XJ_EUOY7kJnV832uLd9m.GNjQavwpwWIM6sqaDjxVQNxVIdYSzzSUS3%2Bjo%2BhD4RY; Path=/; HttpOnly
    var elements = (cookieStr + "").split(';');
    for (var e in elements) {
        if (elements[e].indexOf(config.auth_session_cookie.name) == 0) {
            return elements[e].split("=")[1].trim();
        }
    }
    return 'not found';
}





