'use strict';

const db = require('../../../../models/index');
const requestHelper = require('../../../request-helper');
const initData = require('../setup/init-data');
const login = require('../setup/login');

function change_email_test_suite(authenticate, change_password) {
    context('with correct information', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            const newEmail = 'new_email@second.org';
            const password = initData.USER_1.password;
            change_password.call(this, newEmail, password, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(200);
            expect(this.res.body.success).equal(true);
        });

        it('should have generated a token', function(done) {
            user_should_have_a_generated_token(done);
        });
    });

    context('trying with a wrong password', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, 'new_email@second.org', initData.USER_1.password + 'madeWrong!', done);

        });

        it('should report a failure forbidden', function() {
            expect(this.res.statusCode).equal(403);
            expect(this.res.body.success).equal(false);
            expect(this.res.body.reason).equal('WRONG_PASSWORD');
        });

        it('should not have generated a token', function(done) {
            user_should_not_have_generated_a_token(done);
        });
    });

    context('trying to set an already chosen email', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, initData.USER_2.email, initData.USER_1.password, done);

        });

        it('should report a failure email token', function() {
            expect(this.res.statusCode).equal(400);
            expect(this.res.body.success).equal(false);
            expect(this.res.body.reason).equal('EMAIL_ALREADY_TAKEN');
        });

        it('should not have generated a token', function(done) {
            user_should_not_have_generated_a_token(done);
        });
    });

    context('trying to set an already chosen email (case sensitive)', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, initData.USER_2.email.toUpperCase(), initData.USER_1.password, done);
        });

        it('should report a failure email token', function() {
            expect(this.res.statusCode).equal(400);
            expect(this.res.body.success).equal(false);
            expect(this.res.body.reason).equal('EMAIL_ALREADY_TAKEN');
        });

        it('should not have generated a token', function(done) {
            user_should_not_have_generated_a_token(done);
        });
    });

    context('trying five times', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, 'n1@one.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n2@two.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n3@three.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n4@four.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n5@five.org', initData.USER_1.password, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(200);
            expect(this.res.body.success).equal(true);
        });

        it('should have five tokens', function(done) {
            user_should_have_five_tokens(done);

        });
    });

    context('trying too often', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, 'n1@one.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n2@two.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n3@three.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n4@four.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n5@five.org', initData.USER_1.password, done);
        });
        before(function(done) {
            change_password.call(this, 'n6@six.org', initData.USER_1.password, done);
        });

        it('should report a failure', function() {
            expect(this.res.statusCode).equal(429);
            expect(this.res.body.success).equal(false);
        });

        it('should have five tokens', function(done) {
            user_should_have_five_tokens(done);
        });
    });
}

describe('API V2 POST change email', function() {

    context('Using session', function() {
        change_email_test_suite(login.session_authenticate, change_password_with_session);
    });

    context('Using oauth', function() {
        change_email_test_suite(login.oAuth_authenticate, change_password_with_oauth);
    });
});

// oAuth

function change_password_with_oauth(newEmail, password, done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/oauth/user/email/change',
        {
            method: 'post',
            accessToken: this.accessToken,
            tokenType: 'Bearer',
            data: {
                new_email: newEmail,
                password: password
            }
        },
        done
    );
}

function change_password_with_session(newEmail, password, done) {
    requestHelper.sendRequest(
        this,
        '/api/v2/session/user/email/change',
        {
            method: 'post',
            cookie: this.cookie,
            data: {
                new_email: newEmail,
                password: password
            }
        },
        done
    );
}

// Checks

function user_should_have_a_generated_token(done) {
    db.UserEmailToken.findOne({where: {user_id: initData.USER_1.id}}).then(
        function(token) {
            expect(token).a('object');
            expect(token.type).match(/^MOV\$/);
            done();
        }
    ).catch(done);
}

function user_should_not_have_generated_a_token(done) {
    db.UserEmailToken.findOne({where: {user_id: initData.USER_1.id}}).then(
        function(token) {
            expect(token).equal(null);
            done();
        }
    ).catch(done);
}

function user_should_have_five_tokens(done) {
    db.UserEmailToken.count({where: {user_id: initData.USER_1.id}}).then(
        function(count) {
            expect(count).equal(5);
            done();
        }
    ).catch(done);
}

