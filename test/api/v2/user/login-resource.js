"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var config = require('../../../../config');
var login = require('../setup/login');
var userHelper = require('../../../../lib/user-helper');
var db = require('../../../../models');
var codeHelper = require('../../../../lib/code-helper');


// Google reCAPTCHA
var recaptcha = require('express-recaptcha');

// The following recaptcha key should always return ok
// See https://developers.google.com/recaptcha/docs/faq
const OK_RECATCHA_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
const OK_RECATCHA_SECRET = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';
const recaptchaResponse = 'a dummy recaptcha response';

// The following recaptacha key should always return ko
const KO_RECATCHA_KEY = 'ko';
const KO_RECATCHA_SECRET = 'ko';

const AN_EMAIL = 'mail@mail.mail';
const LONG_MAIL = 'thisis@nemailthatisvery.cool';
const STRONG_PASSWORD = 'correct horse battery staple';
const WEAK_PASSWORD = 'weak';
const DATE_OF_BIRTH = '31.08.1978';

const WHITELISTED_REDIRECT_URI = 'http://whitelistedredirecturl.com'
const NOT_WHITELISTED_REDIRECT_URI = 'http://notwhitelistedredirecturl.com'

const AFTER_LOGIN = {
    activated: true,
    cookieName: 'peach_infos',
    domain: 'http://localhost.rts.ch:3000',
    duration: 999999999,
    storeUserId: true,
    storeUserDisplayName: false
};

describe('API-V2 LOGIN', function () {

    before(function (done) {

        if (config.afterLogin) {
            config.afterLogin.allowedRedirectUris = WHITELISTED_REDIRECT_URI;
        } else {
            config.afterLogin = {allowedRedirectUris: WHITELISTED_REDIRECT_URI};
        }
        done();
    });

    context('signup', function () {
        beforeEach(initData.resetEmptyDatabase);

        context('session', function () {
            context('When unauthenticated user cookieSignup with bad recaptcha', function () {
                var ctx = this;
                before(function (done) {
                    recaptcha.init(KO_RECATCHA_KEY, KO_RECATCHA_SECRET);
                    done();
                });

                before(function (done) {
                    login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                });

                it('should return a success false', function () {
                    expect(ctx.res.statusCode).to.equal(400);
                    expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- reCaptcha is empty or wrong.","errors":[{"field":"g-recaptcha-response","type":"BAD_FORMAT_OR_MISSING","hint":"Fail to validate Recaptcha","message":"reCaptcha is empty or wrong.","data":"invalid-input-response"}]}}');
                });

            });
            context('When unauthenticated user cookieSignup with good recaptcha', function () {

                before(function (done) {
                    recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
                    done();
                });

                context('When unauthenticated user cookieSignup with weak password', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, WEAK_PASSWORD, null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- Password too simple. Use numbers and upper and lower case letters.","errors":[{"field":"password","type":"CUSTOM","custom_type":"PASSWORD_WEAK","hint":"Password is too weak","message":"Password too simple. Use numbers and upper and lower case letters."}]}}');
                     });

                });

                context('When unauthenticated user cookieSignup with email as password', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, LONG_MAIL, LONG_MAIL, null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- Password too simple. Use numbers and upper and lower case letters.","errors":[{"field":"password","type":"CUSTOM","custom_type":"PASSWORD_WEAK","hint":"Password is too weak","message":"Password too simple. Use numbers and upper and lower case letters."}]}}');
                     });

                });

                context('When unauthenticated user cookieSignup with good recaptcha', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                    });

                    it('should return a success true', function () {
                        expect(ctx.res.statusCode).to.equal(204);
                    });

                });

                context('When unauthenticated user cookieSignup without password', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, 'qsdf2@qsdf.fr', null, null, null, done);
                    });


                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- Missing password","errors":[{"field":"password","type":"MISSING","hint":"Password is mandatory","message":"Missing password"}]}}');
                    });

                });

                context('When unauthenticated user cookieSignup without mail', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, null, STRONG_PASSWORD, null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- Email is empty","errors":[{"field":"email","type":"MISSING","hint":"\\"email\\" is not present in request body","message":"Email is empty"}]}}');
                    });

                });

                context('When 2 users register with same mail', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                    });

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD + "2", null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"That email is already taken","errors":[{"field":"email","type":"CUSTOM","custom_type":"EMAIL_TAKEN","hint":"Email mail@mail.mail already taken as social or local login","message":"<br/>- That email is already taken"}]}}');
                    });

                });
                context('When 2 users register with same mail case sensitive', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                    });

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL.toUpperCase(), STRONG_PASSWORD + "2", null, null, done);
                    });


                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"That email is already taken","errors":[{"field":"email","type":"CUSTOM","custom_type":"EMAIL_TAKEN","hint":"Email MAIL@MAIL.MAIL already taken as social or local login","message":"<br/>- That email is already taken"}]}}');
                    });

                });

                context('and some required fields', function () {
                    var preFields;
                    before(function () {
                        preFields = config.userProfiles.requiredFields;
                        config.userProfiles.requiredFields = ['gender', 'date_of_birth'];
                        userHelper.reloadConfig();
                    });
                    after(function () {
                        config.userProfiles.requiredFields = preFields;
                        userHelper.reloadConfig();
                    });

                    context('When unauthenticated user cookieSignup without all required fields', function () {
                        var ctx = this;

                        before(function (done) {
                            login.cookieSignupWithProfile(ctx, AN_EMAIL, STRONG_PASSWORD, {gender: 'male'}, null, null, done);
                        });


                        it('should return a success false', function () {
                            expect(ctx.res.statusCode).equal(400);
                            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- date_of_birth  is missing","errors":[{"field":"date_of_birth","type":"MISSING","hint":"field \\"date_of_birth\\" is missing","message":"date_of_birth  is missing"}]}}');
                        });

                    });

                    context('When unauthenticated user cookieSignup with badly formatted field', function () {
                        var ctx = this;


                        before(function (done) {
                            login.cookieSignupWithProfile(ctx, AN_EMAIL, STRONG_PASSWORD, {
                                gender: 'jedi',
                                date_of_birth: DATE_OF_BIRTH
                            }, null, null, done);
                        });

                        it('should return a success false', function () {
                            expect(ctx.res.statusCode).equal(400);
                            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"Some fields are missing or have a bad format see errors arrays","message":"You did not supply all required information<br/>- undefined","errors":[{"field":"gender","type":"BAD_FORMAT","custom_type":"Unknown gender \'jedi\' should one of the following (male|female|other)","hint":" - gender doesn\'t have the expected format"}]}}');
                        });
                    });

                    context('When unauthenticated user cookieSignup with correct fields', function () {
                        var ctx = this;

                        before(function (done) {
                            login.cookieSignupWithProfile(ctx, 'qsdf@qsdf.fr'.toUpperCase(), STRONG_PASSWORD + "2", {
                                gender: 'female',
                                date_of_birth: DATE_OF_BIRTH
                            }, null, null, done);
                        });

                        it('should return a success true no content', function () {
                            expect(ctx.res.statusCode).equal(204);
                        });
                    });
                });

                context('When unauthenticated user cookieSignup with optionnals fields and no fields are required', function () {
                    var ctx = this;

                    var preFields;

                    before(function () {
                        preFields = config.userProfiles.requiredFields;
                        config.userProfiles.requiredFields = [];
                        userHelper.reloadConfig();
                    });
                    after(function () {
                        config.userProfiles.requiredFields = preFields;
                        userHelper.reloadConfig();
                    });

                    before(function (done) {
                        login.cookieSignupWithProfile(ctx, AN_EMAIL, STRONG_PASSWORD, {
                            gender: 'female',
                            date_of_birth: DATE_OF_BIRTH,
                            firstname: 'firstname',
                            lastname: 'lastname'
                        }, null, null, done);
                    });

                    before(function (done) {
                        db.User.findOne().then(function (profile) {
                            ctx.user = profile;
                        }).then(done);
                    });

                    it('should save fields', function () {
                        expect('female').equal(ctx.user.gender);
                        expect('firstname').equal(ctx.user.firstname);
                        expect('lastname').equal(ctx.user.lastname);
                        expect("1978-08-31").equal(ctx.user.date_of_birth_ymd);
                    });
                });

                context('When unauthenticated user cookieSignup with locale in request headers and no fields are required', function () {
                    var ctx = this;

                    var preFields;

                    before(function () {
                        preFields = config.userProfiles.requiredFields;
                        config.userProfiles.requiredFields = [];
                        userHelper.reloadConfig();
                    });
                    after(function () {
                        config.userProfiles.requiredFields = preFields;
                        userHelper.reloadConfig();
                    });

                    before(function (done) {

                        var data = {
                            email: AN_EMAIL,
                            password: STRONG_PASSWORD,
                            'g-recaptcha-response': 'a dummy recaptcha response'
                        };

                        var uri = '/api/v2/session/signup';

                        requestHelper.sendRequest(ctx, uri, {
                            method: 'post',
                            type: 'form',
                            data: data,
                            locale: 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7'
                        }, done);

                    });

                    before(function (done) {
                        db.User.findOne().then(function (profile) {
                            ctx.user = profile;
                        }).then(done);
                    });

                    it('language should be set', function () {
                        expect('fr').equal(ctx.user.language);
                    });
                });
                context('When unauthenticated user cookieSignup with unsupported locale in request headers and no fields are required', function () {
                    var ctx = this;

                    var preFields;

                    before(function () {
                        preFields = config.userProfiles.requiredFields;
                        config.userProfiles.requiredFields = [];
                        userHelper.reloadConfig();
                    });
                    after(function () {
                        config.userProfiles.requiredFields = preFields;
                        userHelper.reloadConfig();
                    });

                    before(function (done) {

                        var data = {
                            email: AN_EMAIL,
                            password: STRONG_PASSWORD,
                            'g-recaptcha-response': 'a dummy recaptcha response'
                        };

                        var uri = '/api/v2/session/signup';

                        requestHelper.sendRequest(ctx, uri, {
                            method: 'post',
                            type: 'form',
                            data: data,
                            locale: 'cn-cn'
                        }, done);

                    });

                    before(function (done) {
                        db.User.findOne().then(function (profile) {
                            ctx.user = profile;
                        }).then(done);
                    });

                    it('language should be set', function () {
                        expect('cn').equal(ctx.user.language);
                    });
                });

            });
            context('after signup', function () {

                context('user should have an authenticated cookie session ', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                    });

                    before(function (done) {
                        requestHelper.sendRequest(ctx, '/api/v2/session/user/profile', {
                            method: 'get',
                            cookie: ctx.cookie
                        }, done);
                    });

                    it('should return a success true', function () {
                        expect(ctx.res.statusCode).to.equal(200);
                    });

                });
            });
            context('when user request to be redirected', function () {
                context('with code', function () {
                    context('with whitelisted uri', function () {

                        var ctx = this;

                        before(function (done) {
                            login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, WHITELISTED_REDIRECT_URI, true, done);
                        });

                        it('should return a 302', function () {
                            expect(ctx.res.statusCode).to.equal(302);
                            expect(ctx.res.header.location).to.equal('/ap/api/v2/session/cookie?redirect=' + WHITELISTED_REDIRECT_URI);
                        });
                    });
                    context('with not whitelisted uri', function () {

                        var ctx = this;

                        before(function (done) {
                            login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, NOT_WHITELISTED_REDIRECT_URI, true, done);
                        });

                        it('should return a 400', function () {
                            expect(ctx.res.statusCode).to.equal(400);
                            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"UNAUTHORIZED_REDIRECT_URI","hint":"redirect uri http://notwhitelistedredirecturl.com is not an allowed redirection","errors":[]}}');
                        });
                    });
                });
                context('without code', function () {

                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, WHITELISTED_REDIRECT_URI, null, done);
                    });

                    it('should return a 302', function () {
                        expect(ctx.res.statusCode).to.equal(302);
                        expect(ctx.res.header.location).to.equal(WHITELISTED_REDIRECT_URI);
                    });
                });
            });
        });

        context('jwt', function () {
            context('after signup', function () {

                context('user should have an authenticated cookie session ', function () {
                    var ctx = this;

                    before(function (done) {
                        login.jwtSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                    });

                    before(function (done) {
                        requestHelper.sendRequest(ctx, '/api/v2/jwt/user/profile', {
                            method: 'get',
                            accessToken: ctx.token,
                            tokenType: 'JWT'
                        }, done);
                    });

                    it('should return a success true', function () {
                        expect(ctx.res.statusCode).to.equal(200);
                    });

                });
            });
        });
    });

    context('login', function () {
        before(initData.resetDatabase);
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
                it('should return unauthorize', function () {
                    expect(ctx.res.statusCode).equal(401);
                });
            });
            context('with redirects and no code', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithRedirectOption(ctx, WHITELISTED_REDIRECT_URI, false, done);
                });
                it('should return a 302 at request location', function () {
                    expect(ctx.res.statusCode).equal(302);
                    expect(ctx.res.headers["location"]).equal(WHITELISTED_REDIRECT_URI);
                });
            });
            context('with redirects and code', function () {
                context('with whitelisted uri', function () {

                    var ctx = this;
                    before(function (done) {
                        login.cookieLoginWithRedirectOption(ctx, WHITELISTED_REDIRECT_URI, true, done);
                    });
                    it('should return a 302 redirect to /api/v2/session/cookie', function () {
                        expect(ctx.res.statusCode).equal(302);
                        expect(ctx.res.headers["location"]).equal('/ap/api/v2/session/cookie?redirect=' + WHITELISTED_REDIRECT_URI);
                    });
                });
                context('with whitelisted uri', function () {

                    var ctx = this;
                    before(function (done) {
                        login.cookieLoginWithRedirectOption(ctx, NOT_WHITELISTED_REDIRECT_URI, true, done);
                    });
                    it('should return a 400', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"UNAUTHORIZED_REDIRECT_URI","hint":"redirect uri http://notwhitelistedredirecturl.com is not an allowed redirection","errors":[]}}');
                    });


                });
            });
            context('Cookie', function () {
                var ctx = this;
                var firstCookie;
                var secondCookie;
                before(function (done) {
                    login.cookieLogin(ctx, function(){
                        firstCookie = ctx.cookie[0];
                        done();
                    });
                });

                before(function (done) {
                    login.cookieLogin(ctx, function(){
                        secondCookie = ctx.cookie[0];
                        done();
                    });
                });

                it('should change', function () {
                    expect(firstCookie).not.equal(secondCookie);
                });
            });
        });
    });


    context('remove account', function () {

        var ctx = this;


        before(function (done) {
            db.User.count({}).then(function (count) {
                ctx.countBefore = count;
                done();
            });
        });

        context('using basic auth', function () {
            before(function (done) {
                login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
            });
            before(function (done) {
                requestHelper.sendRequest(ctx, '/api/v2/basicauth/user', {method: 'delete', cookie: context.cookie, basicAuth: {login: AN_EMAIL, password: STRONG_PASSWORD}}, done);
            });

            before(function (done) {
                db.User.count({}).then(function (count) {
                    ctx.count = count;
                    done();
                });
            });

            it('user should be deleted', function () {
                expect(ctx.countBefore).to.equal(ctx.count);
            });

            it('should return a 204', function () {
                expect(ctx.res.statusCode).to.equal(204);
            });

        });
        context('using jwt', function () {
            before(function (done) {
                login.jwtSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
            });
            before(function (done) {
                requestHelper.sendRequest(ctx, '/api/v2/jwt/user', {method: 'delete', accessToken: ctx.token}, done);

            });

            before(function (done) {
                db.User.count({}).then(function (count) {
                    ctx.count = count;
                    done();
                });
            });

            it('User should be deleted', function () {
                expect(ctx.countBefore).to.equal(ctx.count);
            });

            it('should return a 204', function () {
                expect(ctx.res.statusCode).to.equal(204);
            });
        });
        context('using session (with local login)', function () {
            before(function (done) {
                login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
            });
            before(function (done) {
                requestHelper.sendRequest(ctx, '/api/v2/session/user', {method: 'delete', cookie: ctx.cookie}, done);
            });

            before(function (done) {
                db.User.count({}).then(function (count) {
                    ctx.count = count;
                    done();
                });
            });

            it('user should not be deleted', function () {
                expect(ctx.countBefore + 1).to.equal(ctx.count);
            });

            it('should return a 412', function () {
                expect(ctx.res.statusCode).to.equal(412);
                expect(ctx.res.text).to.equal('{"error":{"status":412,"code":"USER_HAS_LOCAL_LOGIN","hint":"When user has local login, he has to use the authenticated endpoint /api/v2/basicauth/user","errors":[]}}');
            });

        });

    });
    context('retrieve session token', function () {
        before(initData.resetDatabase);
        context('session', function () {
            context('with redirects and code', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLoginWithRedirectOption(ctx, WHITELISTED_REDIRECT_URI, true, done);
                });
                before(function (done) {
                    requestHelper.sendRequest(ctx, '/api/v2/session/cookie?redirect=' + encodeURIComponent(WHITELISTED_REDIRECT_URI), {cookie: ctx.cookie}, done);
                });
                it('should return a 302 redirect to /api/v2/session/cookie', function () {
                    expect(ctx.res.statusCode).equal(302);
                    expect(ctx.res.headers["location"]).equal(WHITELISTED_REDIRECT_URI + '?token=' + getCookieValue(ctx.cookie));
                });
            });
        });
    });

    context('logout', function () {
        before(initData.resetDatabase);
        context('session', function () {
            context('with valid session', function () {
                var ctx = this;

                before(function (done) {
                    login.cookieLogin(ctx, done);
                });

                before(function (done) {
                    login.cookieLogout(ctx, done);
                });

                it('should return a success without content', function () {
                    expect(ctx.res.statusCode).equal(204);
                });
            });

            context('without session', function () {
                var ctx = this;

                before(function (done) {
                    login.cookieLogout(ctx, done);
                });

                it('should return unauthorize', function () {
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

                it('should return unauthorize', function () {
                    expect(ctx.res.statusCode).equal(401);
                });
            });

            context('Cookie', function () {
                var ctx = this;
                var firstCookie;
                var secondCookie;
                before(function (done) {
                    login.cookieLogin(ctx, function(){
                        firstCookie = ctx.cookie[0];
                        done();
                    });
                });

                before(function (done) {
                    login.cookieLogout(ctx, function(){
                        secondCookie = ctx.cookie[0];
                        done();
                    });
                });

                it('should change', function () {
                    expect(firstCookie).not.equal(secondCookie);
                });
            });
        });
    });

    context('Peach info cookie', function () {
        context('after login', function () {
            before(initData.resetDatabase);

            before(function (done) {
                if (config.afterLogin) {
                    config.afterLogin.storeUserInfoInCookie = AFTER_LOGIN;
                } else {
                    config.afterLogin = {storeUserInfoInCookie: AFTER_LOGIN};
                }
                done();
            });

            context('When after login is set', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieLogin(ctx, done);
                });
                it('should return a set cookie header', function () {
                    expect(ctx.res.statusCode).equal(204);
                    expect(ctx.res.header["set-cookie"].length).to.be.above(1);
                    expect(ctx.res.header["set-cookie"][0].indexOf("peach_infos=")).equal(0);

                });
            });
        });

        context('after signup', function () {
            before(initData.resetDatabase);

            before(function (done) {
                if (config.afterLogin) {
                    config.afterLogin.storeUserInfoInCookie = AFTER_LOGIN;
                } else {
                    config.afterLogin = {storeUserInfoInCookie: AFTER_LOGIN};
                }
                done();
            });

            context('When after login is set', function () {
                var ctx = this;
                before(function (done) {
                    login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
                });
                it('should return a set cookie header', function () {
                    expect(ctx.res.statusCode).equal(204);
                    expect(ctx.res.header["set-cookie"].length).to.be.above(1);
                    expect(ctx.res.header["set-cookie"][0].indexOf("peach_infos=")).equal(0);

                });
            });
        });
    });
});

describe('API-V2 GET JWT Token', function () {
    before(initData.resetDatabase);


    context('when user has a session', function () {
        var ctx = this;
        before(function (done) {
            login.cookieLogin(ctx, done);
        });
        before(function (done) {
            requestHelper.sendRequest(ctx, '/api/v2/session/jwt', {cookie: ctx.cookie}, done);
        });
        it('should return a success', function () {
            expect(ctx.res.statusCode).equal(200);
            expect(ctx.res.body.token);
            expect(ctx.res.body.token.indexOf("JWT ")).equal(0);
        });
    });

    context('when user doesn\'t have  a session', function () {
        var ctx = this;
        before(function (done) {
            login.cookieLogin(ctx, done);
        });
        before(function (done) {
            requestHelper.sendRequest(ctx, '/api/v2/session/jwt', {}, done);
        });
        it('should return a success', function () {
            expect(ctx.res.statusCode).equal(401);
        });
    });
});

describe('API-V2 PASSWORD RECOVERY', function() {

    let ctx = this;

    let recoverPassword = function(email, response, done) {

        requestHelper.sendRequest(ctx, '/api/v2/all/password/recover', {
            method: 'post',
            cookie: ctx.cookie,
            data: {
                email: email,
                'g-recaptcha-response': response
            }
        }, done);
    };

    before(initData.resetDatabase);

    before(function(done) {
        login.cookieSignup(ctx, AN_EMAIL, STRONG_PASSWORD, null, null, done);
    });

    context('When user try to recover password with valid email and good recaptcha', function() {

        // Google reCAPTCHA
        before(function(done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });


        before(function(done) {
            recoverPassword(AN_EMAIL, recaptchaResponse, done);
        });

        it('should return a success ', function() {
            expect(ctx.res.statusCode).to.equal(204);
        });
    });

    context('When user try to recover password with valid email (case insensitive) and good recaptcha', function() {


        // Google reCAPTCHA
        before(function(done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });

        before(function(done) {
            recoverPassword(AN_EMAIL.toUpperCase(), recaptchaResponse, done);
        });

        it('should return a success ', function() {
            expect(ctx.res.statusCode).to.equal(204);
        });
    });

    context('When user try to recover password with valid email and bad recaptcha', function() {

        // Google reCAPTCHA
        before(function(done) {
            recaptcha.init(KO_RECATCHA_KEY, KO_RECATCHA_SECRET);
            done();
        });

        before(function(done) {
            recoverPassword(AN_EMAIL.toUpperCase(), 'dewdew', done);
        });

        it('should return a 400 error', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"they might be several causes see errors array","message":[{"field":"g-recaptcha-response","type":"BAD_FORMAT_OR_MISSING","hint":"Bad recaptcha","message":"Something went wrong with the reCAPTCHA"}],"errors":[]}}');
        });
    });

    context('When user try to recover password with an invalid email and good recaptcha', function() {


        // Google reCAPTCHA
        before(function(done) {
            recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
            done();
        });

        before(function(done) {
            recoverPassword('qsdfcewhfuwehweih@qsdf.fr', recaptchaResponse, done);
        });

        it('should return a 400 error', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"USER_NOT_FOUND","hint":"Cannot find an account with email \'qsdfcewhfuwehweih@qsdf.fr\' as local login","message":"User not found","errors":[]}}');
        });
    });

});


describe('API-V2 PASSWORD UPDATE', function() {

    let ctx = this;

    let validCode;

    let updatePassword = function(email, newPassword, code, done) {
        let data = {}
        if (email){
            data.email = email;
        }
        if (newPassword){
            data.password = newPassword;
        }
        if (code){
            data.code = code;
        }
        requestHelper.sendRequest(ctx, '/api/v2/all/password/update', {
            method: 'post',
            cookie: ctx.cookie,
            data: data
        }, done);
    };


    before(initData.resetDatabase);

    before(function(done) {
        codeHelper.generatePasswordRecoveryCode(initData.USER_1_ID).then(function (code) {
            validCode = code;
            done();
        });
    });

    context('When user try to update his password with wrong code', function() {


        before(function(done) {
            updatePassword(initData.USER_1.email, STRONG_PASSWORD, "WrongCode", done);
        });

        it('should return a 400 with expect standard error ', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"They might be several causes see errors array","message":"Wrong recovery code.","errors":[{"field":"code","type":"CUSTOM","custom_type":"WRONG_CODE","hint":"wrong code","message":"Wrong recovery code."}]}}');
        });
    });

    context('When user try to update his password without code', function() {

        before(function(done) {
            updatePassword(initData.USER_1.email, STRONG_PASSWORD, undefined, done);
        });

        it('should return a 400 with expect standard error ', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"They might be several causes see errors array","errors":[{"field":"code","type":"MISSING","hint":"\\"code\\" is not present in request body"}]}}');
        });
    });

    context('When user try to update his password with a weak password', function() {

        before(function(done) {
            updatePassword(initData.USER_1.email, 'w', validCode, done);
        });

        it('should return a 400 with expect standard error ', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.text).to.equal('{"error":{"status":400,"code":"BAD_DATA","hint":"They might be several causes see errors array","errors":[{"field":"password","type":"CUSTOM","custom_type":"OWASP_0"},{"field":"password","type":"CUSTOM","custom_type":"OWASP_4"},{"field":"password","type":"CUSTOM","custom_type":"OWASP_5"},{"field":"password","type":"CUSTOM","custom_type":"OWASP_6"}]}}');
        });
    });

    context('When user try to update his password with an unexisting email', function() {

        before(function(done) {
            updatePassword("unexisting@unexisting.ebu.io", STRONG_PASSWORD, validCode, done);
        });

        it('should return a 400 with expect standard error ', function() {
            expect(ctx.res.statusCode).to.equal(400);
            expect(ctx.res.body.error.status).to.equal(400);
            expect(ctx.res.body.error.code).to.equal("NO_USER_FOR_THIS_MAIL");
            expect(ctx.res.body.error.hint).to.equal("No user found for the following email 'unexisting@unexisting.ebu.io'");
            expect(ctx.res.body.error.message).to.equal("User not found.");
            expect(ctx.res.body.error.errors.length).to.equal(0);
        });
    });

    context('When user try to update his password with correct data', function() {

        before(function(done) {
            updatePassword(initData.USER_1.email, STRONG_PASSWORD, validCode, done);
        });

        it('should return a 204', function() {
            expect(ctx.res.statusCode).to.equal(204);
        });
    });

    context('When user try to update his password with correct data and tries to login', function() {

        before(function(done) {
            updatePassword(initData.USER_1.email, STRONG_PASSWORD, validCode, done);
        });

        before(function(done) {
            login.cookieLoginWithCustomCrendentials(ctx, initData.USER_1.email, STRONG_PASSWORD, done);
        });

        it('should return a 204', function() {
            expect(ctx.res.statusCode).to.equal(204);
        });

    });

    context('When user try to update his password with correct data and tries to login with previous password', function() {

        before(function(done) {
            updatePassword(initData.USER_1.email, STRONG_PASSWORD, validCode, done);
        });

        before(function(done) {
            login.cookieLoginWithCustomCrendentials(ctx, initData.USER_1.email, initData.USER_1.password, done);
        });

        it('should return a 401', function() {
            expect(ctx.res.statusCode).to.equal(401);
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





