'use strict';

var promise = require('bluebird');
var bcrypt = promise.promisifyAll(require('bcrypt'));

var db = require('../../../../models');
var dbHelper = require('../../../db-helper');
var generate = require('../../../../lib/generate');

var USER_1_CPA_TOKEN = generate.cryptoCode(20);
var USER_2_CPA_TOKEN = generate.cryptoCode(20);

var OAUTH_CLIENT_1 = {
    id: 1,
    client_id: 'ClientA',
    client_secret: 'ClientSecret',
    name: 'OAuth 2.0 Client',
    redirect_uri: 'http://localhost'
};

var USER_1_ID = 123;

var USER_1 = {
    id: USER_1_ID,
    email: 'test@test.com',
    account_uid: 'RandomUid',
    password: 'a'
};

var USER_1_DAB_STR = '2018-07-14';

var USER_1_PROFILE = {
    firstname: 'John',
    lastname: 'Doe',
    display_name: 'John Doe',
    gender: 'M',
    date_of_birth: new Date(USER_1_DAB_STR).getTime(),
    date_of_birth_ymd: USER_1_DAB_STR,
    language: 'FR',
    public_uid: '2b61aade-f9b5-47c3-8b5b-b9f4545ec9f9'
};

var USER_2_ID = 234;

var USER_2 = {
    id: USER_2_ID,
    email: 'test2@test.com',
    account_uid: 'RandomUid2',
    password: 'b'
};

var USER_2_DAB_STR = '2018-08-15';

var USER_2_PROFILE = {
    firstname: 'Franck',
    lastname: 'Holmes',
    display_name: 'Franck Holmes',
    gender: 'M',
    date_of_birth: new Date(USER_2_DAB_STR).getTime(),
    date_of_birth_ymd: USER_2_DAB_STR,
    language: 'FR',
    public_uid: '2b61aade-f9b5-47c3-8b5b-b9f4545ec9f8'
};

module.exports = {
    OAUTH_CLIENT_1: OAUTH_CLIENT_1,
    USER_1: USER_1,
    USER_2: USER_2,
    USER_1_ID: USER_1_ID,
    USER_2_ID: USER_2_ID,
    USER_1_PROFILE: USER_1_PROFILE,
    USER_2_PROFILE: USER_2_PROFILE,
    USER_1_DAB_STR: USER_1_DAB_STR,
    USER_2_DAB_STR: USER_2_DAB_STR,
    USER_1_CPA_TOKEN: USER_1_CPA_TOKEN,
    USER_2_CPA_TOKEN: USER_2_CPA_TOKEN,
    resetDatabase: resetDatabase,
    resetEmptyDatabase: resetEmptyDatabase,
};

function createOAuth2Client(done) {
    db.OAuth2Client.create(OAUTH_CLIENT_1).then(
        function(client) {
            return client.updateAttributes({client_secret: bcrypt.hashSync(OAUTH_CLIENT_1.client_secret, 5)});
        }
    ).then(
        function() {
            done();
        }
    ).catch(
        function(err) {
            return done(err);
        }
    );
}

function createUser(userTemplate) {
    return db.User.create(userTemplate).then(function(user) {
        return db.LocalLogin.create({
            user_id: user.id,
            login: userTemplate.email
        }).then(function(localLogin) {
            return localLogin.setPassword(userTemplate.password).then(function() {
                return user.updateAttributes(USER_1_PROFILE);
            });
        }).then(function() {
            return db.AccessToken.create({
                token: USER_1_CPA_TOKEN,
                user_id: user.id
            });
        });
    });
}

function createUsers(done) {
    createUser(USER_1).then(() => {
        return createUser(USER_2);
    }).then(() => {
        return done();
    }).catch(done);
}

function resetDatabase(done) {
    return dbHelper.clearDatabase(function(err) {
        if (err) {
            return done(err);
        } else {
            return createOAuth2Client(
                function() {
                    return createUsers(function() {
                        done();
                    });
                }
            );
        }
    });
}

function resetEmptyDatabase(done) {
    return dbHelper.clearDatabase(function(err) {
        if (err) {
            return done(err);
        } else {
            return createOAuth2Client(
                function() {
                    done();
                }
            );
        }
    });
}