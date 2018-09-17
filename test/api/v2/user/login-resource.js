"use strict";

var requestHelper = require('../../../request-helper');
var initData = require('../setup/init-data');
var config = require('../../../../config');
var login = require('../setup/login');
var userHelper = require('../../../../lib/user-helper');
var db = require('../../../../models');


// Google reCAPTCHA
var recaptcha = require('express-recaptcha');

// The following recaptcha key should always return ok
// See https://developers.google.com/recaptcha/docs/faq
const OK_RECATCHA_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI';
const OK_RECATCHA_SECRET = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

// The following recaptacha key should always return ko
const KO_RECATCHA_KEY = 'ko';
const KO_RECATCHA_SECRET = 'ko';

const AN_EMAIL = 'mail@mail.mail';
const LONG_MAIL = 'thisis@nemailthatisvery.cool';
const STRONG_PASSWORD = 'correct horse battery staple';
const WEAK_PASSWORD = 'weak';
const DATE_OF_BIRTH = 249782400000;

const WHITELISTED_REDIRECT_URI = 'http://whitelistedredirecturl.com'
const NOT_WHITELISTED_REDIRECT_URI = 'http://notwhitelistedredirecturl.com'

const API_PASSWORD_RECOVER_SOMETHING_WRONG_RECAPTCHA = 'Something went wrong with the reCAPTCHA';

describe('API-V2 LOGIN', function () {

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
                    expect(ctx.res.body.msg).to.equal('RECAPTCHA_ERROR');
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
                        expect(ctx.res.body.msg.indexOf("Password is not strong enough")).to.equal(0);
                        expect(ctx.res.statusCode).to.equal(400);
                    });

                });

                context('When unauthenticated user cookieSignup with email as password', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, LONG_MAIL, LONG_MAIL, null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.body.msg.indexOf("Password is not strong enough")).to.equal(0);
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
                        expect(ctx.res.body.msg).to.equal("missing required fields");
                        expect(ctx.res.body.data);
                        expect(ctx.res.body.missingFields);
                        expect(ctx.res.body.data.missingFields[0]).to.equal('password');
                    });

                });

                context('When unauthenticated user cookieSignup without mail', function () {
                    var ctx = this;

                    before(function (done) {
                        login.cookieSignup(ctx, null, STRONG_PASSWORD, null, null, done);
                    });

                    it('should return a success false', function () {
                        expect(ctx.res.statusCode).to.equal(400);
                        expect(ctx.res.body.msg).to.equal("missing required fields");
                        expect(ctx.res.body.data);
                        expect(ctx.res.body.missingFields);
                        expect(ctx.res.body.data.missingFields[0]).to.equal('email');
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
                        expect(ctx.res.body.msg).to.equal("email already exists");
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
                        expect(ctx.res.body.msg).to.equal("email already exists");
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
                            expect(ctx.res.body.msg).equal("missing required fields");
                            expect(ctx.res.body.data.missingFields).members(['date_of_birth']);
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
                            expect(ctx.res.body.msg).equal("UNKNOWN_GENDER");
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

                        it('should return a success false', function () {
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
                        expect(DATE_OF_BIRTH).equal(ctx.user.date_of_birth);
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
                            expect(ctx.res.body.msg).to.equal('redirect uri ' + NOT_WHITELISTED_REDIRECT_URI + ' is not an allowed redirection');
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
            context('when user request to be redirected', function () {
                var ctx = this;

                context('with code', function () {

                    before(function (done) {
                        login.jwtSignup(ctx, AN_EMAIL, STRONG_PASSWORD, WHITELISTED_REDIRECT_URI, true, done);
                    });

                    it('should return a 302', function () {
                        expect(ctx.res.statusCode).to.equal(302);
                        expect(ctx.res.header.location).to.equal(WHITELISTED_REDIRECT_URI + '?token=' + ctx.token);
                    });
                });
                context('without code', function () {

                    before(function (done) {
                        login.jwtSignup(ctx, AN_EMAIL, STRONG_PASSWORD, WHITELISTED_REDIRECT_URI, null, done);
                    });

                    it('should return a 302', function () {
                        expect(ctx.res.statusCode).to.equal(302);
                        expect(ctx.res.header.location).to.equal(WHITELISTED_REDIRECT_URI);
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
                it('should return a success', function () {
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
                        expect(ctx.res.body.msg).to.equal('redirect uri ' + NOT_WHITELISTED_REDIRECT_URI + ' is not an allowed redirection');
                    });


                });
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





