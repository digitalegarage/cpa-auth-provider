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

const API_PASSWORD_RECOVER_SOMETHING_WRONG_RECAPTCHA = 'Something went wrong with the reCAPTCHA';

function signupWithProfile(email, password, profileData, done) {
    var data = {
        email: email,
        password: password,
        confirm_password: password, //FIXME: remove that!!!
        'g-recaptcha-response': 'a dummy recaptcha response'
    };
    data = Object.assign(data, profileData);

    requestHelper.sendRequest(this, '/api/v2/session/signup', {
        method: 'post',
        cookie: this.cookie,
        type: 'form',
        data: data
    }, done);
}

function signup(email, password, done) {
    signupWithProfile.call(this, email, password, null, done);
}

describe('API-V2 LOGIN', function () {

    context('signup', function () {
        beforeEach(initData.resetEmptyDatabase);

        context('session', function () {
            context('When unauthenticated user signup with bad recaptcha', function () {

                before(function (done) {
                    recaptcha.init(KO_RECATCHA_KEY, KO_RECATCHA_SECRET);
                    done();
                });

                before(function (done) {
                    signup.call(this, AN_EMAIL, STRONG_PASSWORD, done);
                });

                it('should return a success false', function () {
                    expect(this.res.statusCode).to.equal(400);
                    expect(this.res.body.msg).to.equal(API_PASSWORD_RECOVER_SOMETHING_WRONG_RECAPTCHA);
                });

            });
            context('When unauthenticated user signup with good recaptcha', function () {

                before(function (done) {
                    recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
                    done();
                });

                context('When unauthenticated user signup with weak password', function () {

                    before(function (done) {
                        signup.call(this, AN_EMAIL, WEAK_PASSWORD, done);
                    });

                    it('should return a success false', function () {
                        expect(this.res.body.msg.indexOf("Password is not strong enough")).to.equal(0);
                        expect(this.res.statusCode).to.equal(400);
                    });

                });

                context('When unauthenticated user signup with email as passord', function () {

                    before(function (done) {
                        signup.call(this, LONG_MAIL, LONG_MAIL, done);
                    });

                    it('should return a success false', function () {
                        expect(this.res.statusCode).to.equal(400);
                        expect(this.res.body.msg.indexOf("Password is not strong enough")).to.equal(0);
                    });

                });

                context('When unauthenticated user signup with good recaptcha', function () {

                    before(function (done) {
                        signup.call(this, AN_EMAIL, STRONG_PASSWORD, done);
                    });

                    it('should return a success true', function () {
                        expect(this.res.statusCode).to.equal(204);
                    });

                });

                context('When unauthenticated user signup without password', function () {

                    before(function (done) {
                        signup.call(this, 'qsdf2@qsdf.fr', null, done);
                    });


                    it('should return a success false', function () {
                        expect(this.res.statusCode).to.equal(400);
                        expect(this.res.body.msg).to.equal("Please pass email and password");
                    });

                });

                context('When unauthenticated user signup without mail', function () {

                    before(function (done) {
                        signup.call(this, null, STRONG_PASSWORD, done);
                    });

                    it('should return a success false', function () {
                        expect(this.res.statusCode).to.equal(400);
                        expect(this.res.body.msg).to.equal("Please pass email and password");
                    });

                });

                context('When 2 users register with same mail', function () {

                    before(function (done) {
                        signup.call(this, AN_EMAIL, STRONG_PASSWORD, done);
                    });

                    before(function (done) {
                        signup.call(this, AN_EMAIL, STRONG_PASSWORD + "2", done);
                    });

                    it('should return a success false', function () {
                        expect(this.res.statusCode).to.equal(400);
                        expect(this.res.body.msg).to.equal("email already exists");
                    });

                });
                context('When 2 users register with same mail case sensitive', function () {
                    before(function (done) {
                        signup.call(this, AN_EMAIL, STRONG_PASSWORD, done);
                    });

                    before(function (done) {
                        signup.call(this, AN_EMAIL.toUpperCase(), STRONG_PASSWORD + "2", done);
                    });


                    it('should return a success false', function () {
                        expect(this.res.statusCode).to.equal(400);
                        expect(this.res.body.msg).to.equal("email already exists");
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

                    context('When unauthenticated user signup without all required fields', function () {

                        before(function (done) {
                            signupWithProfile.call(this, AN_EMAIL, STRONG_PASSWORD, {gender: 'male'}, done);
                        });


                        it('should return a success false', function () {
                            expect(this.res.statusCode).equal(400);
                            expect(this.res.body.msg).equal("missing required fields");
                            expect(this.res.body.missingFields).members(['date_of_birth']);
                        });

                    });

                    context('When unauthenticated user signup with badly formatted field', function () {


                        before(function (done) {
                            signupWithProfile.call(this, AN_EMAIL, STRONG_PASSWORD, {
                                gender: 'jedi',
                                date_of_birth: 249782400000
                            }, done);
                        });

                        it('should return a success false', function () {
                            expect(this.res.statusCode).equal(400);
                            expect(this.res.body.msg).equal("missing required fields");
                            expect(this.res.body.missingFields).undefined;
                        });
                    });

                    context('When unauthenticated user signup with correct fields', function () {

                        before(function (done) {
                            signupWithProfile.call(this, 'qsdf@qsdf.fr'.toUpperCase(), STRONG_PASSWORD + "2", {
                                gender: 'female',
                                date_of_birth: 249782400000
                            }, done);
                        });

                        it('should return a success false', function () {
                            expect(this.res.statusCode).equal(204);
                        });
                    });
                });

                context('When unauthenticated user signup with optionnals fields and no fields are required', function () {
                    var self = this;

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
                        signupWithProfile.call(this, AN_EMAIL, STRONG_PASSWORD, {
                            gender: 'female',
                            date_of_birth: 249782400000,
                            firstname: 'firstname',
                            lastname: 'lastname'
                        }, done);
                    });

                    before(function (done) {
                        db.User.findOne().then(function (profile) {
                            self.user = profile;
                        }).then(done);
                    });

                    it('should save fields', function () {
                        expect('female').equal(self.user.gender);
                        expect('firstname').equal(self.user.firstname);
                        expect('lastname').equal(self.user.lastname);
                        expect(249782400000).equal(self.user.date_of_birth);
                    });
                });
            });
        });
    });
    // TODO expect to be logged after signup
    // TODO Date format
    // TODO clean signup endpoint
    // TODO test redirect
    // TODO remove password confirm from required field

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
        before(initData.resetDatabase);
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





