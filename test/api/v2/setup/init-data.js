var promise = require('bluebird');
var bcrypt = promise.promisifyAll(require('bcrypt'));

var db = require('../../../../models');
var dbHelper = require('../../../db-helper');
var generate = require('../../../../lib/generate');

var USER_1_CPA_TOKEN = generate.cryptoCode(20);


var OAUTH_CLIENT_1 = {
    id: 1,
    client_id: "ClientA",
    client_secret: "ClientSecret",
    name: "OAuth 2.0 Client",
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
    gender: 'M',
    date_of_birth: new Date(USER_1_DAB_STR).getTime(),
    date_of_birth_ymd: USER_1_DAB_STR,
    language: 'FR'
};

module.exports = {
    OAUTH_CLIENT_1: OAUTH_CLIENT_1,
    USER_1: USER_1,
    USER_1_PROFILE: USER_1_PROFILE,
    USER_1_DAB_STR: USER_1_DAB_STR,
    USER_1_CPA_TOKEN: USER_1_CPA_TOKEN,
    resetDatabase: resetDatabase
}

function createOAuth2Client(done) {
    db.OAuth2Client.create(OAUTH_CLIENT_1).then(
        function (client) {
            return client.updateAttributes({client_secret: bcrypt.hashSync(OAUTH_CLIENT_1.client_secret, 5)});
        }
    ).then(
        function () {
            done();
        }
    ).catch(
        function (err) {
            return done(err);
        }
    );
}

function createUser(userTemplate) {
    return db.User.create(userTemplate).then(function (user) {
        return db.LocalLogin.create({
            user_id: user.id,
            login: userTemplate.email
        }).then(function (localLogin) {
            return localLogin.setPassword(userTemplate.password).then(function () {
                return user.updateAttributes(USER_1_PROFILE);
            });
        }).then(function(){
            return db.AccessToken.create({
                token: USER_1_CPA_TOKEN,
                user_id: user.id
            });
        });
    });
}

function createUsers(done) {
    createUser(USER_1).then(
        function () {
            return done();
        }
    ).catch(done);
}


function resetDatabase(done) {
    return dbHelper.clearDatabase(function (err) {
        if (err) {
            return done(err);
        } else {
            return createOAuth2Client(
                function () {
                    return createUsers(function () {
                        done();
                    });
                }
            );
        }
    });
};