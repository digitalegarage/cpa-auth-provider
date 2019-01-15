"use strict";

var requestHelper = require('../request-helper');
var dbHelper = require('../db-helper');

var resetDatabase = function (done) {
    dbHelper.clearDatabase(function (err) {
        done(err);
    });
};

var recaptchaResponse = 'a dummy recaptcha response';

var STRONG_PASSWORD = 'correct horse battery staple';

// Test authenticate

describe('GET /api/local/request_verification_email', function () {


    context('When unauthenticated user signup with correct credential request a new validation email', function () {

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

        // Test resend validation mail
        before(function (done) {
            this.accessToken = this.res.body.token.substring(4, this.res.body.token.size);

            requestHelper.sendRequest(this, '/api/local/request_verification_email', {
                    method: 'get',
                    accessToken: this.accessToken,
                    tokenType: 'JWT'
                }, done
            );
        });

        it('/api/local/request_verification_email should return a success ', function () {
            expect(this.res.statusCode).to.equal(204);
        });
    });


});
