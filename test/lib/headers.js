"use strict";

var config = require('../../config');

var requestHelper = require("../request-helper");


describe('Check response for headers', function () {
    before(function (done) {
        requestHelper.sendRequest(this, '/auth', null, done);
    });

    it('should set x-frame-options', function () {
        expect(this.res.header['x-frame-options']).to.equal('ALLOW-FROM ' + config.iframes.allow_from_domain);
    });
    it('must not set x-powered-by headers', function() {
      expect(this.res.header['x-powered-by']).to.equal(undefined);
    });
});
