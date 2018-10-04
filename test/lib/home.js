"use strict";

var db = require('../../models');
var config = require('../../config');

var chai = require('chai');
var chaiJquery = require('chai-jquery');
var chaiHttp = require('chai-http');
var i18n4test = require("i18n");

var requestHelper = require('../request-helper');

i18n4test.configure({
    locales: ['en'],
    directory: __dirname + '/../../locales'
});

config.broadcaster.title = "";

var resetDatabase = function (done) {
    db.sequelize.query('DELETE FROM Users')
        .then(function () {
            db.sequelize.query('DELETE FROM LocalLogins');
        })
        .then(function () {
            return db.User.create({
                provider_uid: 'testuser'
            });
        })
        .then(function (user) {
            return db.LocalLogin.create({user_id: user.id, login: 'testuser'}).then(function (localLogin) {
                return localLogin.setPassword('testpassword');
            });
        })
        .then(function () {
                done();
            },
            function (error) {
                done(error);
            });
};

describe('GET /', function () {
    before(resetDatabase);

    context('with a signed in user and no landing page', function () {
        var use_landing_page = config.use_landing_page;
        before(function (done) {
            config.use_landing_page = false;
            done();
        });

        after(function (done) {
            config.use_landing_page = use_landing_page;
            done();
        });

        before(function (done) {
            requestHelper.login(this, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/', {cookie: this.cookie}, done);
        });

        it('should redirect to /user/profile', function () {
            var urlPrefix = requestHelper.urlPrefix;
            expect(this.res.statusCode).to.equal(302);
            expect(this.res.headers).to.have.property('location');
            expect(this.res.headers.location).to.equal(urlPrefix + '/user/profile');
        });
    });

    context('with a signed in user and using landing page', function () {
        var use_landing_page = config.use_landing_page;
        before(function (done) {
            config.use_landing_page = true;
            done();
        });

        after(function (done) {
            config.use_landing_page = use_landing_page;
            done();
        });

        before(function (done) {
            requestHelper.login(this, done);
        });

        before(function (done) {
            requestHelper.sendRequest(this, '/', {cookie: this.cookie}, done);
        });

        it('should redirect to /home', function () {
            var urlPrefix = requestHelper.urlPrefix;
            expect(this.res.statusCode).to.equal(302);
            expect(this.res.headers).to.have.property('location');
            expect(this.res.headers.location).to.equal(urlPrefix + '/home');
        });
    });

    context('with no signed in user', function () {
        before(function (done) {
            requestHelper.sendRequest(this, '/', null, done);
        });

        it('should redirect to /auth', function () {
            var urlPrefix = requestHelper.urlPrefix;
            expect(this.res.statusCode).to.equal(302);
            expect(this.res.headers).to.have.property('location');
            expect(this.res.headers.location).to.equal(urlPrefix + '/login?redirect=' + encodeURIComponent(urlPrefix + '/'));
        });
    });
});