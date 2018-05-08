/* jshint node:true, expr:true, esversion:6 */
"use strict";

const config = require('../../config.dist'),
      cors = require('../../lib/cors');


const originDomain = 'https://foobar.br.de';
const invalidOrigin = 'http://noir.org';
const staticOrigin = 'http://localhost.rts.ch:8080';
// be warned: validity of allowed_domains depends on the environment you are running. double check it, NODE_ENV=test !

describe("cors.wildcard_request", (done) => {
  it("should accept a matching request", () => {
    let req,res,next;
    req = fakeRequest({origin: originDomain});
    res = fakeResponse();
    next = () => {
      expect(res.getHeader('Access-Control-Allow-Origin')).to.equal(originDomain);
    };
    cors(req, res, next);
  });
  it("should deny on non-matching domain", () => {
    let req,res,next;
    req = fakeRequest({origin: invalidOrigin});
    res = fakeResponse();
    next = () => {
      expect(res.getHeader('Access-Control-Allow-Origin')).to.equal(undefined);
    };
    cors(req, res, next);
  });
  it("should accept a matching allowed_domain", () => {
    let req,res,next;
    req = fakeRequest({origin: staticOrigin});
    res = fakeResponse();
    next = () => {
      expect(res.getHeader('Access-Control-Allow-Origin')).to.equal(staticOrigin);
    };
    cors(req, res, next);
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
