"use strict";

var cheerio = require('cheerio');

module.exports = {

    urlPrefix: '',

    /**
     * Helper function for making HTTP requests and handling responses.
     *
     * @param {Object} context           Context object
     * @param {String} path              The URL or path for the HTTP request
     * @param {Object} opts              Option settings
     * @param {String} opts.method       HTTP verb: 'get', 'post', 'delete', etc
     * @param {String} opts.cookie       Session cookie
     * @param {String} opts.accessToken  If present, sets an 'Authorization' header with
     *                                   the given access token. The token type is set
     *                                   using the tokenType option
     * @param {String} opts.tokenType    If an accessToken is supplied, this option sets
     *                                   the associated token type (default: 'Bearer')
     * @param {Object} opts.data         A data object to be sent in the HTTP request.
     * @param {String} opts.type         The data encoding format to use, either 'json'
     *                                   (for application/json) or 'form' (for
     *                                   application/x-www-form-urlencoded).
     *                                   Default: 'json'
     * @param {Boolean} parseDOM         If true, parses the HTTP response using the
     *                                   cheerio package, and sets context.$
     * @param {Function} done            Callback fuction, invoked when the HTTP request
     *                                   has completed
     */

    sendRequest: function (context, path, opts, done) {
        opts = opts || {};

        path = this.urlPrefix + path;

        var method = opts.method || 'get';

        if (method === 'delete') {
            method = 'del';
        }

        var req = request[method](path);

        if (opts.cookie) {
            req.set('cookie', opts.cookie);
        }

        if (opts.accessToken) {
            var tokenType = opts.tokenType || 'Bearer';
            req.set('Authorization', tokenType + ' ' + opts.accessToken);
        }

        if (opts.basicAuth) {
            req.set('Authorization', 'Basic' + ' ' + Buffer.from(opts.basicAuth.login + ':' + opts.basicAuth.password).toString('base64'));
        }

        if (opts.data) {
            // If 'form', sets Content-Type: application/x-www-form-urlencoded.
            var type = opts.type || 'json';
            req.type(type);

            req.send(opts.data);
        }

        req.end(function (err, res) {
            if (res && res.headers['set-cookie']) {
                context.cookie = res.headers['set-cookie'];
            }

            context.res = res;

            if (opts.parseDOM) {
                context.$ = cheerio.load(context.res.text);
            }

            done(err);
        });
    },

    login: function (context, done) {
        this.loginCustom('testuser', 'testpassword', context, done);
    },

    loginCustom: function (email, password, context, done) {
        var loginUrl = this.urlPrefix + '/api/v2/session/login';

        request
            .post(loginUrl)
            .type('form')
            .send({email: email, password: password})
            .end(function (err, res) {
                context.cookie = res.headers['set-cookie'];
                done(err);
            });
    },

    loginUser: function (context, username, password, done) {
        var loginUrl = this.urlPrefix + '/api/v2/session/login';

        request
            .post(loginUrl)
            .type('form')
            .send({email: username, username: username, password: password})
            .end(function (err, res) {
                context.cookie = res.headers['set-cookie'];
                done(err);
            });
    }
};
