'use strict';

const requestHelper = require('../../../request-helper');
const initData = require('../setup/init-data');
const login = require('../setup/login');


describe('API V2 request validation email', function() {

    context('Using session', function() {
        request_validation_email_test_suite(login.session_authenticate, request_validation_email_with_session);
    });

    context('Using oauth', function() {
        request_validation_email_test_suite(login.oAuth_authenticate, request_validation_email_with_oauth);
    });

    context('Using jwt', function() {
        request_validation_email_test_suite(login.jwt_authenticate, request_validation_email_with_jwt);
    });

    context('Using cpa', function() {
        request_validation_email_test_suite(login.cpa_authenticate, request_validation_email_with_cpa);
    });
});

function request_validation_email_test_suite(authenticate, request_validation_email) {
    context('Basic test', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            request_validation_email.call(this, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(204);
        });
    });
}

// Request validation email with different security protocol
// oAuth

function request_validation_email_with_oauth(done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/oauth/user/profile/request_verification_email',
        {
            method: 'post',
            accessToken: this.accessToken,
            tokenType: 'Bearer',
            data: {}
        },
        done
    );
}

function request_validation_email_with_session(done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/session/user/profile/request_verification_email',
        {
            method: 'post',
            cookie: this.cookie,
            data: {}
        },
        done
    );
}

function request_validation_email_with_jwt(done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/jwt/user/profile/request_verification_email',
        {
            method: 'post',
            accessToken: this.token,
            data: {}
        },
        done
    );
}

function request_validation_email_with_cpa(done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/cpa/user/profile/request_verification_email',
        {
            method: 'post',
            accessToken: this.token,
            data: {}
        },
        done
    );
}
