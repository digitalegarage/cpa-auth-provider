"use strict";

var generate = require('../../lib/generate');
var db = require('../../models');
var config = require('../../config');
var userHelper = require('../../lib/user-helper');

var requestHelper = require('../request-helper');
var dbHelper = require('../db-helper');

// Google reCAPTCHA
var recaptcha = require('express-recaptcha');

var resetDatabase = function (done) {
    return dbHelper.clearDatabase(function (err) {
        return done(err);
    });
};

var INCORRECT_LOGIN_OR_PASS = 'The username or password is incorrect';
var API_PASSWORD_RECOVER_SOMETHING_WRONG_RECAPTCHA = 'Something went wrong with the reCAPTCHA';
var API_PASSWORD_RECOVER_USER_NOT_FOUND = 'User not found';

var recaptchaResponse = 'a dummy recaptcha response';

// The following recaptcha key should always return ok
// See https://developers.google.com/recaptcha/docs/faq
var OK_RECATCHA_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
var OK_RECATCHA_SECRET = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// The following recaptacha key should always return ko
var KO_RECATCHA_KEY = 'ko';
var KO_RECATCHA_SECRET = 'ko';

var LONG_MAIL = 'thisis@nemailthatisvery.cool';

var STRONG_PASSWORD = 'correct horse battery staple';
var WEAK_PASSWORD = 'weak';

// Test password recovery

describe('POST /api/local/password/recover', function () {

    context('When user try to recover password with valid email and good recaptcha', function () {

        before(resetDatabase);

        // Google reCAPTCHA
        before(function (done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/local/password/recover', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        it('should return a success ', function () {
            expect(this.res.statusCode).to.equal(204);
        });
    });

    context('When user try to recover password with valid email (case insensitive) and good recaptcha', function () {

        before(resetDatabase);

        // Google reCAPTCHA
        before(function (done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/local/password/recover', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr'.toUpperCase(),
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        it('should return a success ', function () {
            expect(this.res.statusCode).to.equal(204);
        });
    });

    context('When user try to recover password with valid email and bad recaptcha', function () {
        before(resetDatabase);

        // Google reCAPTCHA
        before(function (done) {
            recaptcha.init(KO_RECATCHA_KEY, KO_RECATCHA_SECRET);
            done();
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        it('should return a success false', function () {
            expect(this.res.body.msg).to.not.equal("msg:Something went wrong with the reCAPTCHA");
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/local/password/recover', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    'g-recaptcha-response': 'dewdew'
                }
            }, done);
        });

        it('should return a 400 error', function () {
            expect(this.res.statusCode).to.equal(400);
            expect(this.res.text).to.equal('{"error":{"status":400,"code":"INVALID_RECAPTCHA","hint":"Invalid recaptcha.","message":"Something went wrong with the reCAPTCHA","errors":[]}}');
        });
    });

    context('When user try to recover password with not existing email and good recaptcha', function () {
        before(resetDatabase);

        // Google reCAPTCHA
        before(function (done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/local/password/recover', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdfcewhfuwehweih@qsdf.fr',
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        it('should return a 400 error', function () {
            expect(this.res.statusCode).to.equal(400);
            expect(this.res.text).to.equal('{"error":{"status":400,"code":"USER_NOT_FOUND","hint":"Cannot find an account with email \'qsdfcewhfuwehweih@qsdf.fr\' as local login","message":"User not found","errors":[]}}');
        });
    });

});


// Test authenticate

describe('POST /api/v2/jwt/login', function () {

    context('When unauthenticated user signup with correct credential', function () {

        before(resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/jwt/login', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD
                }
            }, done);
        });

        // Test get user info
        before(function (done) {
            this.accessToken = this.res.body.token.substring(4, this.res.body.token.size);
            requestHelper.sendRequest(this, '/api/local/info', {
                    method: 'get',
                    accessToken: this.accessToken,
                    tokenType: 'JWT'
                }, done
            );
        });

        it('/api/local/info should return a success ', function () {
            expect(this.accessToken.length).to.be.greaterThan(0);
            expect(this.res.statusCode).to.equal(200);
            expect(this.res.body.success).to.equal(true);
            expect(this.res.body.user.email).to.equal('qsdf@qsdf.fr');
            expect(this.res.body.user.display_name).to.equal('qsdf@qsdf.fr');

        });
    });
    context('When unauthenticated user signup with correct credential (case insensitive)', function () {

        before(resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/jwt/login', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr'.toUpperCase(),
                    password: STRONG_PASSWORD
                }
            }, done);
        });

        // Test get user info
        before(function (done) {
            this.accessToken = this.res.body.token.substring(4, this.res.body.token.size);
            requestHelper.sendRequest(this, '/api/local/info', {
                    method: 'get',
                    accessToken: this.accessToken,
                    tokenType: 'JWT'
                }, done
            );
        });

        it('/api/local/info should return a success ', function () {
            expect(this.accessToken.length).to.be.greaterThan(0);
            expect(this.res.statusCode).to.equal(200);
            expect(this.res.body.success).to.equal(true);
            expect(this.res.body.user.email).to.equal('qsdf@qsdf.fr');
            expect(this.res.body.user.display_name).to.equal('qsdf@qsdf.fr');

        });
    });

    context('When unauthenticated user signup with email "like" another user email', function () {

        before(resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'first-email@mail.com',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });


        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'email@mail.com',
                    password: STRONG_PASSWORD + "2",
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });


        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/login', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'email@mail.com',
                    password: STRONG_PASSWORD
                }
            }, done);
        });


        it('should 401', function () {
            expect(this.res.statusCode).to.equal(401);
        });
    });

    // Check that the like SQL function has no side effect
    context('When unauthenticated user tries to login with email that is a sub part of another login', function () {

        var aLogin = 'qsdf@qsdf.fr';

        before(resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: aLogin,
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/jwt/login', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'a' + aLogin + 'a',
                    password: STRONG_PASSWORD
                }
            }, done);
        });

        it('/api/local/info should return a 401 ', function () {
            expect(this.token).to.be.undefined;
            expect(this.res.statusCode).to.equal(401);
            expect(this.res.text).to.equal('{"error":{"status":401,"code":"INCORRECT_LOGIN_OR_PASSWORD","hint":"Incorrect login or password","message":"The username or password is incorrect","errors":[]}}');
        });
    });

    context('When unauthenticated user signup with bad credential', function () {

        before(resetDatabase);

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/session/signup', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: STRONG_PASSWORD,
                    'g-recaptcha-response': recaptchaResponse
                }
            }, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/api/v2/jwt/login', {
                method: 'post',
                cookie: this.cookie,
                type: 'form',
                data: {
                    email: 'qsdf@qsdf.fr',
                    password: 'badpass'
                }
            }, done);
        });

        it('should return a 401 ', function () {
            expect(this.token).to.be.undefined;
            expect(this.res.statusCode).to.equal(401);
            expect(this.res.text).to.equal('{"error":{"status":401,"code":"INCORRECT_LOGIN_OR_PASSWORD","hint":"Incorrect login or password","message":"The username or password is incorrect","errors":[]}}');
        });
    });


});