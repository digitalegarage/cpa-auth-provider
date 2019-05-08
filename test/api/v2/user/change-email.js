'use strict';

const db = require('../../../../models/index');
const requestHelper = require('../../../request-helper');
const initData = require('../setup/init-data');
const login = require('../setup/login');
const finder = require('../../../../lib/finder');
const config = require('../../../../config');

describe('API V2 POST change email', function() {

    context('Using session', function() {
        change_email_test_suite(login.session_authenticate, change_email_with_session);
    });

    context('Using oauth', function() {
        change_email_test_suite(login.oAuth_authenticate, change_email_with_oauth);
    });

    context('Using jwt', function() {
        change_email_test_suite(login.jwt_authenticate, change_email_with_jwt);
    });

    context('Using cpa', function() {
        change_email_test_suite(login.cpa_authenticate, change_email_with_cpa);
    });
});

describe('API V2 GET /api/v2/all/user/email/move/:token', function() {
    const URL = '/api/v2/all/user/email/move/{token}';
    const NEW_EMAIL = 'number2@second.org';
    const VALID_TOKEN = 'ABC';
    const send_valid_change_token = function(done) {
        requestHelper.sendRequest(
            this,
            URL.replace(/{token}/, VALID_TOKEN),
            {
                method: 'get'
            },
            done
        );
    };
    const send_wrong_token = function(done) {
        requestHelper.sendRequest(
            this,
            URL.replace(/{token}/, 'wrong'),
            {
                method: 'get',
                cookie: this.cookie,
                accessToken: this.accessToken
            },
            done
        );
    };
    const send_wrong_token_with_redirect = function(done) {
        requestHelper.sendRequest(
            this,
            URL.replace(/{token}/, 'wrong') + '?use_custom_redirect=true',
            {
                method: 'get',
                cookie: this.cookie,
                accessToken: this.accessToken
            },
            done
        );
    };

    context('with correct token', function() {
        before(initData.resetDatabase);
        before(createToken(VALID_TOKEN, NEW_EMAIL, initData.USER_1));
        before(send_valid_change_token);

        it('should send success status', function() {
            expect(this.res.statusCode).equal(200);
        });

        it('should change the email', function(done) {
            check_email_has_been_changed(NEW_EMAIL, done);
        });
    });

    context('with redirect', function() {
        var back = config.broadcaster.changeMoveEmailConfirmationPage;
        before(function(done){
            config.broadcaster.changeMoveEmailConfirmationPage =  'http://localhost/changemailresult.html';
            done();
        });
        after(function(done){
            config.broadcaster.changeMoveEmailConfirmationPage =  back;
            done();
        });

        before(initData.resetDatabase);
        before(createToken(VALID_TOKEN, NEW_EMAIL, initData.USER_1));
        before(send_valid_change_token);

        it('should redirect', function() {
            expect(this.res.statusCode).equal(302);
            expect(this.res.header.location).to.equal('http://localhost/changemailresult.html?success=true');

        });

        it('should change the email', function(done) {
            check_email_has_been_changed(NEW_EMAIL, done);
        });
    });

    context('using a correct token twice', function() {
        before(initData.resetDatabase);
        before(createToken(VALID_TOKEN, NEW_EMAIL, initData.USER_1));

        before(send_valid_change_token);
        before(send_valid_change_token);

        it('should send success status', function() {
            expect(this.res.statusCode).equal(200);
        });

        it('should have changed the email', function(done) {
            check_email_has_been_changed(NEW_EMAIL, done);

        });
    });

    context('using the wrong token', function() {
        before(initData.resetDatabase);
        before(createToken(VALID_TOKEN, NEW_EMAIL, initData.USER_1));

        before(send_wrong_token);

        it('should report a failure', function() {
            expect(this.res.statusCode).equal(200);
            expect(this.res.text.indexOf('Invalid token for authentication') > 0).equal(true);
        });

        it('should not have changed the email', function(done) {
            check_email_hasn_t_changed(done);
        });
    });

    context('using the wrong token and redirect', function() {
        var back = config.broadcaster.changeMoveEmailConfirmationPage;
        before(function(done){
            config.broadcaster.changeMoveEmailConfirmationPage =  'http://localhost/changemailresult.html';
            done();
        });
        after(function(done){
            config.broadcaster.changeMoveEmailConfirmationPage =  back;
            done();
        });
        before(initData.resetDatabase);
        before(createToken(VALID_TOKEN, NEW_EMAIL, initData.USER_1));

        before(send_wrong_token_with_redirect);

        it('should redirect and indicate a failure', function() {
            expect(this.res.statusCode).equal(302);
            expect(this.res.header.location).to.equal('http://localhost/changemailresult.html?success=false');
        });

        it('should not have changed the email', function(done) {
            check_email_hasn_t_changed(done);
        });
    });

});

function change_email_test_suite(authenticate, change_password) {
    context('with correct information', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            const newEmail = 'new_email@second.org';
            const password = initData.USER_1.password;
            change_password.call(this, newEmail, password, null, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(204);
        });

        it('should have generated a token', function(done) {
            user_should_have_a_generated_token(done);
        });
    });

    context('trying with a wrong password', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, 'new_email@second.org', initData.USER_1.password + 'madeWrong!', null, done);

        });

        it('should report a failure forbidden', function() {
            expect(this.res.statusCode).equal(403);
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
            change_password.call(this, initData.USER_2.email, initData.USER_1.password, null, done);

        });

        it('should report a failure email token', function() {
            expect(this.res.statusCode).equal(400);
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
            change_password.call(this, initData.USER_2.email.toUpperCase(), initData.USER_1.password, null, done);
        });

        it('should report a failure email token', function() {
            expect(this.res.statusCode).equal(400);
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
            change_password.call(this, 'n1@one.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n2@two.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n3@three.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n4@four.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n5@five.org', initData.USER_1.password, null, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(204);
        });

        it('should have five tokens', function(done) {
            user_should_have_five_tokens(done);

        });
    });

    context('trying too often', function() {
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            change_password.call(this, 'n1@one.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n2@two.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n3@three.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n4@four.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n5@five.org', initData.USER_1.password, null, done);
        });
        before(function(done) {
            change_password.call(this, 'n6@six.org', initData.USER_1.password, null, done);
        });

        it('should report a failure', function() {
            expect(this.res.statusCode).equal(429);
        });

        it('should have five tokens', function(done) {
            user_should_have_five_tokens(done);
        });
    });
    context('with redirect', function() {
        const redirect = 'http://localhost/';
        before(initData.resetDatabase);
        before(authenticate.call(this));

        before(function(done) {
            const newEmail = 'new_email@second.org';
            const password = initData.USER_1.password;
            change_password.call(this, newEmail, password, redirect, done);
        });

        it('should report a success', function() {
            expect(this.res.statusCode).equal(204);
        });

        it('should have generated a token', function(done) {
            user_should_have_a_generated_token(done);
        });
    });

}

// Change email with different security protocol
// oAuth

function change_email_with_oauth(newEmail, password, redirect, done) {
    let data = {
        new_email: newEmail,
        password: password
    };
    if (redirect) {
        data.redirect = redirect;
    }
    requestHelper.sendRequest(
        this,
        '/api/v2/oauth/user/email/change',
        {
            method: 'post',
            accessToken: this.accessToken,
            tokenType: 'Bearer',
            data: data
        },
        done
    );
}

function change_email_with_session(newEmail, password, redirect, done) {
    let data = {
        new_email: newEmail,
        password: password
    };
    if (redirect) {
        data.redirect = redirect;
    }
    requestHelper.sendRequest(
        this,
        '/api/v2/session/user/email/change',
        {
            method: 'post',
            cookie: this.cookie,
            data: data
        },
        done
    );
}

function change_email_with_jwt(newEmail, password, redirect, done) {
    let data = {
        new_email: newEmail,
        password: password
    };
    if (redirect) {
        data.redirect = redirect;
    }
    requestHelper.sendRequest(
        this,
        '/api/v2/jwt/user/email/change',
        {
            method: 'post',
            accessToken: this.token,
            data: data
        },
        done
    );
}

function change_email_with_cpa(newEmail, password, redirect, done) {
    let data = {
        new_email: newEmail,
        password: password
    };
    if (redirect) {
        data.redirect = redirect;
    }
    requestHelper.sendRequest(
        this,
        '/api/v2/cpa/user/email/change',
        {
            method: 'post',
            accessToken: this.token,
            data: data
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

function check_email_has_been_changed(NEW_EMAIL, done) {
    finder.findUserByLocalAccountEmail(NEW_EMAIL).then(
        function(localLogin) {
            expect(localLogin).a('object');
            expect(localLogin.user_id).equal(initData.USER_1.id);
            expect(localLogin.verified).equal(true);
            done();
        }
    ).catch(done);
}

function check_email_hasn_t_changed(done) {
    db.LocalLogin.findOne({where: {user_id: initData.USER_1.id}}).then(
        function(localLogin) {
            expect(localLogin).a('object');
            expect(localLogin.login).equal(initData.USER_1.email);
            done();
        }
    ).catch(done);
}

// Utils

function createToken(key, address, user) {
    return function(done) {
        db.UserEmailToken.create(
            {
                user_id: user.id,
                key: key,
                type: 'MOV$' + address
            }
        ).then(
            function(t) {
                done();
            },
            done
        );
    };
}


