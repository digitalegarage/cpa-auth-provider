"use strict";

var config = require('../../config');
var db = require('../../models');
var authHelper = require('../../lib/auth-helper');

var requestHelper = require('../request-helper');
var dbHelper = require('../db-helper');

var TEST_USER_LOGIN = "testuser";
var TEST_USER_PASSWORD = "testpassword";
var FIRSTNAME = "John";
var LASTNAME = "Doe";
var GENDER = 'Male';
var DAB_STR = "2018-07-14";
var LANG = "EN";

var initDatabase = function (done) {
    db.User.create({
        provider_uid: 'testuser',
        firstname: FIRSTNAME,
        lastname: LASTNAME,
        gender: GENDER,
        date_of_birth: new Date(DAB_STR).getTime(),
        date_of_birth_ymd: DAB_STR,
        language: LANG
    })
        .then(function (user) {
            return db.LocalLogin.create({user_id: user.id, login: TEST_USER_LOGIN}).then(function (localLogin) {
                return localLogin.setPassword(TEST_USER_PASSWORD);
            });
        })
        .then(function () {
                done();
            },
            function (err) {
                done(new Error(err));
            });
};

var resetDatabase = function (done) {
    return dbHelper.resetDatabase(initDatabase, done);
};

function searchCookie(res) {
    var found = false;
    var setcookie = res.headers["set-cookie"];
    if (setcookie) {
        setcookie.forEach(
            function (cookiestr) {
                if (cookiestr.indexOf('peach_infos') == 0) {
                    found = true;
                }
            }
        );
    }
    return found;
}

describe('POST /authenticate/cookie', function () {
    before(resetDatabase);
    context('When logging in for a session cookie', function () {
        context('with valid credentials', function () {
            before(function (done) {
                config.afterLogin = {
                    storeUserInfoInCookie: {
                        activated: true,
                        cookieName: 'peach_infos',
                        domain: 'toto.com',
                        duration: 999999999,
                        storeUserId: true,
                        storeUserDisplayName: true
                    }
                };
                done();
            });
            after(function (done) {
                config = require('../../config');
                done();
            });
            before(function (done) {
                requestHelper.sendRequest(this, '/api/local/authenticate/cookie', {
                    method: 'post',
                    type: 'json',
                    data: {"email": TEST_USER_LOGIN, "password": TEST_USER_PASSWORD}
                }, done);
            });
            context('when calling auth endpoint', function () {
                it('should answer 204 and a session cookie', function () {
                    expect(this.res.statusCode).to.equal(204);
                });
            });
            context('when accessing the profile with the cookie', function () {
                before(function (done) {
                    requestHelper.sendRequest(this, '/api/session/profile', {
                        method: 'get',
                        cookie: this.cookie
                    }, done);
                });
                it('should response with 200', function () {
                    expect(this.res.statusCode).to.equal(200);
                    expect(this.res.body.user_profile.email).equal(TEST_USER_LOGIN);
                    expect(this.res.body.user_profile.display_name).equal(TEST_USER_LOGIN);
                    expect(this.res.body.user_profile.firstname).equal(FIRSTNAME);
                    expect(this.res.body.user_profile.lastname).equal(LASTNAME);
                    expect(this.res.body.user_profile.gender).equal(GENDER);
                    expect(this.res.body.user_profile.date_of_birth).equal(new Date(DAB_STR).getTime());
                    expect(this.res.body.user_profile.date_of_birth_ymd).equal(DAB_STR);
                    expect(this.res.body.user_profile.language).equal(LANG);
                });
            });
            describe('when config is set to set info cookie', function () {
                it('should return a success with appropriate data in cookie peach_infos', function () {
                    var foundCookie = searchCookie.call(this, this.res);
                    expect(foundCookie).equal(true);
                });
            });

        });
        context('with invalid credentials', function () {
            before(function (done) {
                requestHelper.sendRequest(this, '/api/local/authenticate/cookie', {
                    method: 'post',
                    type: 'json',
                    data: {"email": "foo", "password": "bar"}
                }, done);
            });
            it('should response 401', function () {
                expect(this.res.statusCode).to.equal(401);
            });
        });
        context('with uppercase login', function () {
            before(function (done) {
                requestHelper.sendRequest(this, '/api/local/authenticate/cookie', {
                    method: 'post',
                    type: 'json',
                    data: {"email": TEST_USER_LOGIN.toUpperCase(), "password": TEST_USER_PASSWORD}
                }, done);
            });
            it('should response 204', function () {
                expect(this.res.statusCode).to.equal(204);
            });
        });
    });
});

describe('GET /protected', function () {
    before(resetDatabase);

    context('When the user is not authenticated', function () {
        before(function (done) {
            requestHelper.sendRequest(this, '/protected', null, done);
        });

        it('should return a status 302', function () {
            expect(this.res.statusCode).to.equal(302);
        });
    });

    context('When the user is authenticated', function () {
        before(function (done) {
            requestHelper.login(this, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/protected', {cookie: this.cookie}, done);
        });

        it('should return a status 200', function () {
            expect(this.res.statusCode).to.equal(200);
        });
    });
});
