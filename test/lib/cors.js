/* jshint node:true, expr:true, esversion:6 */
"use strict";

const cors = require('../../lib/cors'),
      config = require('../../config.local');

const wildcardDomain = '.br.de';
const originDomain = 'foobar.br.de';

describe("cors.wildcard_request", (done) => {
  it("should accept a matching request", () => {
    config.cors.use_wildcard_domain = true;
    config.cors.wildcard_domain = wildcardDomain;
    let req,res,next;
    req = fakeRequest({origin: originDomain});
    res = fakeResponse();
    next = () => { return; };
    cors(req, res, next, (err,response) => {
      expect(response).to.equal(originDomain);
    });
  });
  it("should return false on missing wildcard_domain", () => {
    config.cors.use_wildcard_domain = true;
    config.cors.wildcard_domain = undefined;
    let req,res,next;
    req = fakeRequest({origin: originDomain});
    res = fakeResponse();
    next = () => { return; };
    cors(req, res, next, (err,response) => {
      expect(response).to.equal(false);
    });
  });
  it("should return false on non-matching wildcard_domain", () => {
    config.cors.use_wildcard_domain = true;
    config.cors.wildcard_domain = '.kornherr.net';
    let req,res,next;
    req = fakeRequest({origin: originDomain});
    res = fakeResponse();
    next = () => { return; };
    cors(req, res, next, (err,response) => {
      expect(response).to.equal(false);
    });
  });
  it("should return false on non-matching origin", () => {
    config.cors.use_wildcard_domain = true;
    config.cors.wildcard_domain = '.br.de';
    let req,res,next;
    req = fakeRequest({origin: 'www.kornherr.net'});
    res = fakeResponse();
    next = () => { return; };
    cors(req, res, next, (err,response) => {
      expect(response).to.equal(false);
    });
  });
  it("should match example/default domains without wildcards", () => {
    config.cors.use_wildcard_domain = false;
    let req,res,next;
    req = fakeRequest({origin: config.cors.allowed_domains[0]});
    res = fakeResponse();
    next = () => { return; };
    cors(req, res, next, (err,response) => {
      expect(response).to.equal(config.cors.allowed_domains[0]);
    });
  });
});

let fakeRequest = function (headers) {
    return {
      headers: headers || {
        'origin': 'request.com',
        'access-control-request-headers': 'requestedHeader1,requestedHeader2'
      },
      pause: function () {
        // do nothing
        return;
      },
      resume: function () {
        // do nothing
        return;
      }
    };
  },
  fakeResponse = function () {
    var headers = {};
    return {
      allHeaders: function () {
        return headers;
      },
      getHeader: function (key) {
        return headers[key];
      },
      setHeader: function (key, value) {
        headers[key] = value;
        return;
      },
      get: function (key) {
        return headers[key];
      }
    };
  };
