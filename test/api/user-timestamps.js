"use strict";

var requestHelper = require('../request-helper');
var dbHelper = require('../db-helper');
var finder = require ('../../lib/finder');

var resetDatabase = function (done) {
    dbHelper.clearDatabase(function (err) {
        done(err);
    });
};


var TEST_EMAIL_0 = 'qsdf@qsdf.fr';
var OLD_PASSWORD = 'correct horse battery staple';
var NEW_PASSWORD = 'correct horse battery staple 42';
var recaptchaResponse = 'a dummy recaptcha response';

// Test authenticate

describe('user profile timestamps', function () {
    context('account creation', function () {
        var self = this;
        var last_login_at;
        var start_at;

        before(resetDatabase);
        before(function (done) {
            requestHelper.sendRequest(
                this,
                '/api/v2/session/signup',
                {
                    method: 'post',
                    cookie: this.cookie,
                    type: 'form',
                    data: {
                        email: TEST_EMAIL_0,
                        password: OLD_PASSWORD,
                        'g-recaptcha-response': recaptchaResponse
                    }
                },
                function(){
                    finder.findUserByLocalAccountEmail(TEST_EMAIL_0)
                    .then(function (localLogin) {
                        start_at = localLogin.created_at.getTime();
                        done();
                    });
                }
            )
        });

        before(function (done) {
            requestHelper.sendRequest(
                self,
                '/api/v2/session/login',
                {
                    method: 'post',
                    cookie: self.cookie,
                    type: 'form',
                    data: {
                        email: TEST_EMAIL_0,
                        password: OLD_PASSWORD
                    }
                },
                function(){
                    finder.findUserByLocalAccountEmail(TEST_EMAIL_0)
                    .then(function (localLogin) {
                        last_login_at = localLogin.last_login_at;
                        done();
                    });
                }
            );
        });

        before(function (done) {
            finder.findUserByLocalAccountEmail(TEST_EMAIL_0).then(
                function (localLogin) {
                    localLogin.setPassword(NEW_PASSWORD).then(
                        function () {
                            done();
                        },
                        done
                    );
                },
                done
            );
        });

        before(function (done) {
            requestHelper.sendRequest(
                self,
                '/api/v2/session/login',
                {
                    method: 'post',
                    cookie: self.cookie,
                    type: 'form',
                    data: {
                        email: TEST_EMAIL_0,
                        password: OLD_PASSWORD
                    }
                },
                done
            );
        });


        it('should be set to proper time', function (done) {
            finder.findUserByLocalAccountEmail(TEST_EMAIL_0).then(
                function (localLogin) {
                    try {
                        expect(localLogin.created_at.getTime()).not.be.above(last_login_at);
                    } catch (e) {
                        return done(e);
                    }
                    done();
                },
                done
            );
        });

        it('should have proper password set time', function (done) {
            finder.findUserByLocalAccountEmail(TEST_EMAIL_0).then(
                function (localLogin) {
                    try {
                        expect(localLogin.password_changed_at).to.be.above(start_at);
                    } catch (e) {
                        return done(e);
                    }
                    done();
                },
                done
            );
        });

        it('should have proper last login time', function (done) {
            finder.findUserByLocalAccountEmail(TEST_EMAIL_0).then(
                function (localLogin) {
                    try {
                        expect(localLogin.last_login_at).to.be.above(start_at);
                    } catch (e) {
                        return done(e);
                    }
                    done();
                },
                done
            );
        });
    });


});