'use strict';

const
    db = require('../../models'),
    dbHelper = require('../db-helper'),
    recaptcha = require('express-recaptcha'),
    requestHelper = require('../request-helper'),
    recaptchaResponse = 'a dummy recaptcha response',
    OK_RECATCHA_KEY = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
    OK_RECATCHA_SECRET = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe';

const resetDatabase = function (done) {
    dbHelper.clearDatabase(function (err) {
        if (err)
            console.log(err);
        done(err);
    });
};

const PASSWORD = "SuperPeter123!",
      EMAIL    = "peter@kornherr.net",
      EMAIL2   = "ibis@br.de";

const
    old_api_url = '/user/lalalala/password/create',
    new_api_url = '/api/v2/session/user/login/create';

function working_request(ctx,url,done) {
    requestHelper.sendRequest(ctx, '/signup', {
        method: 'post',
        cookie: ctx.cookie,
        type: 'form',
        data: {
            email: EMAIL,
            password: PASSWORD,
            'g-recaptcha-response': recaptchaResponse
        }
    }, done); //() => {
        // requestHelper.sendRequest(
        //     ctx,
        //     url,
        //     {
        //         method: 'post',
        //         cookie: ctx.cookie,
        //         type: 'form',
        //         data: {
        //             email: EMAIL,
        //             password: PASSWORD,
        //             confirm_password: PASSWORD
        //         }
        //     }, done);
//    });
};

function failing_request(ctx,url,done) {
    requestHelper.sendRequest(ctx, '/api/v2/session/signup', {
        method: 'post',
        cookie: ctx.cookie,
        type: 'form',
        data: {
            email: EMAIL,
            password: PASSWORD,
            'g-recaptcha-response': recaptchaResponse
        }
    }, () => {
        requestHelper.sendRequest(
            ctx,
            url,
            {
                method: 'post',
                cookie: ctx.cookie,
                type: 'form',
                data: {
                    email: EMAIL2,
                    password: PASSWORD,
                    confirm_password: PASSWORD
                }
            }, done);
    });
};

describe("oldapi: creating a localLogin", () => {
    let ctx = this;
    let allUsers;

    before(done => {
        resetDatabase(done);
    });

    before(done => {
        db.User.findAll()
        .then(u=>{
            done();
        });
    });

    before(function (done) {
        recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
        done();
    });

    before(function (done) {
        working_request(ctx, old_api_url, done);
    });

    before(done => {
        db.User.findAll({include: ['LocalLogin']})
        .then(users => {
            allUsers = users;
            done();
        });
    });

    it('should return a success and create a localLogin', () => {
        expect(ctx.res.statusCode).to.equal(302);
        expect(allUsers).not.to.be.undefined;
        expect(allUsers).not.to.be.empty;
        expect(allUsers.length).to.equal(1);
        expect(allUsers[0].LocalLogin).not.to.be.undefined;
        expect(allUsers[0].LocalLogin.login).to.equal(EMAIL);
    });
});

describe("oldapi: creating a localLogin but rejecting the 2nd", () => {
    let allUsers;
    let ctx = this;

    before(done => {
        resetDatabase(done);
    });

    before(function (done) {
        recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
        done();
    });

    before(function (done) {
        failing_request(ctx,old_api_url,done);
    });
    before(done => {
        db.User.findAll({include: ['LocalLogin']})
        .then(users => {
            allUsers = users;
            done();
        });
    })

    it('should return a success and create a localLogin, but denying the 2nd', () => {
        expect(allUsers).not.to.be.undefined;
        expect(allUsers).not.to.be.empty;
        expect(allUsers.length).to.equal(1);
        expect(allUsers[0].LocalLogin).not.to.be.undefined;
        expect(allUsers[0].LocalLogin.login).to.equal(EMAIL);
        expect(ctx.res.statusCode).to.equal(500);
    });
});

describe("newapi: creating a localLogin", () => {
    let ctx = this;
    let allUsers;

    before(done => {
        resetDatabase(done);
    });

    before(done => {
        db.User.findAll()
        .then(u=>{
            done();
        });
    });

    before(function (done) {
        recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
        done();
    });

    before(function (done) {
        working_request(ctx, new_api_url, done);
    });

    before(done => {
        db.User.findAll({include: ['LocalLogin']})
        .then(users => {
            allUsers = users;
            done();
        });
    });

    it('should return a success and create a localLogin', () => {
        expect(ctx.res.statusCode).to.equal(302);
        expect(allUsers).not.to.be.undefined;
        expect(allUsers).not.to.be.empty;
        expect(allUsers.length).to.equal(1);
        expect(allUsers[0].LocalLogin).not.to.be.undefined;
        expect(allUsers[0].LocalLogin.login).to.equal(EMAIL);
    });
});


describe("newapi: creating a localLogin but rejecting the 2nd", () => {
    let allUsers;
    let ctx = this;

    before(done => {
        resetDatabase(done);
    });

    before(function (done) {
        recaptcha.init(OK_RECATCHA_KEY, OK_RECATCHA_SECRET);
        done();
    });

    before(function (done) {
        failing_request(ctx,new_api_url,done);
    });
    before(done => {
        db.User.findAll({include: ['LocalLogin']})
        .then(users => {
            allUsers = users;
            done();
        });
    })

    it('should return a success and create a localLogin, but denying the 2nd', () => {
        expect(allUsers).not.to.be.undefined;
        expect(allUsers).not.to.be.empty;
        expect(allUsers.length).to.equal(1);
        expect(allUsers[0].LocalLogin).not.to.be.undefined;
        expect(allUsers[0].LocalLogin.login).to.equal(EMAIL);
        expect(ctx.res.statusCode).to.equal(400);
    });
});