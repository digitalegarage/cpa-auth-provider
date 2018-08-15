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
    it('must use the more-secure-headers', function() {
      expect(this.res.header['x-xss-protection']).to.equal("1; mode=block");
      expect(this.res.header['x-content-type-options']).to.equal("nosniff");
      expect(this.res.header['strict-transport-security']).to.equal("max-age=31536000");
      expect(this.res.header['content-security-policy']).to.equal("default-src data: https: 'self'; script-src https: 'self' 'unsafe-inline' http://connect.facebook.com/ https://broadcarster.org; style-src https: 'self' 'unsafe-inline' https://broadcarster.org; img-src *; frame-src 'self' http://staticxx.facebook.com https://www.google.com https://accounts.google.com/ https://broadcarster.org; connect-src https:; font-src 'self' https://broadcarster.org");
    });
});
