'use strict';

const requestHelper = require('../request-helper'),
    dbHelper = require('../db-helper');

var USER_EMAIL = 'test@somewhe.re';
var STRONG_PASSWORD = 'correct horse battery staple';

describe('Check same site cookie policy', function () {
    before(done => {
        resetDatabase(done);
    });

    before(done => {
        requestHelper.sendRequest(this, '/api/v2/jwt/login', {
            method: 'post',
            cookie: this.cookie,
            type: 'form',
            data: {
                email: USER_EMAIL,
                password: STRONG_PASSWORD
            }
        }, done);
    });
    it('should set samesite on cookie', () => {
        var found = false;
        for (var i = 0; i < this.cookie.length; i++) {
            if (this.cookie[i].indexOf('SameSite=Lax') !== -1)
                found = true;
        }
        expect(found).to.equal(true);
    });
});

var resetDatabase = function (done) {
    return dbHelper.clearDatabase(function (err) {
        return dbHelper.createFakeUser({
            id: 1337,
            email: USER_EMAIL,
            password: STRONG_PASSWORD
        }, done);
    });
};