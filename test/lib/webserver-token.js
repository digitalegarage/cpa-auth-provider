"use strict";

var db       = require('../../models');
var generate = require('../../lib/generate');

var assertions    = require('../assertions');
var requestHelper = require('../request-helper');

var _ = require('lodash');
var async = require('async');

var clearDatabase = function(done) {
  db.sequelize.query('DELETE FROM PairingCodes')
    .then(function() {
      return db.sequelize.query('DELETE FROM AccessTokens');
    })
    .then(function() {
      return db.sequelize.query('DELETE FROM Clients');
    })
    .then(function() {
      return db.sequelize.query('DELETE FROM Users');
    })
    .then(function() {
      return db.sequelize.query('DELETE FROM Domains');
    })
    .then(function() {
      done();
    },
    function(error) {
      done(error);
    });
};

/**
 * For testing,
 */

var createClient = function(callback) {
  db.Client
    .create({
      id:                 100,
      secret:             'e2412cd1-f010-4514-acab-c8af59e5501a',
      name:               'Test client',
      software_id:        'CPA AP Test',
      software_version:   '0.0.1',
      ip:                 '127.0.0.1',
      registration_type:  'dynamic',
      redirect_uri:       'https://example-service.bbc.co.uk/callback'
    }).complete(callback);
};

var createDomain = function(callback) {
  db.Domain.create({
    id:           5,
    name:         'example-service.bbc.co.uk',
    display_name: 'BBC Radio',
    access_token: '70fc2cbe54a749c38da34b6a02e8dfbd'
  }).complete(callback);
};

var createUser = function(callback) {
  db.User.create({
    id:           3,
    provider_uid: 'testuser',
    display_name: 'Test User',
    password:     'testpassword'
  }).complete(callback);
};

var createAuthorizationCode = function(callback) {
  var date = new Date("Wed Apr 09 2014 11:00:00 GMT+0100");

  db.AuthorizationCode.create({
    id:                 50,
    client_id:          100,
    user_id:            3,
    domain_id:          5,
    authorization_code: '4e72e9fdd4bdc3892d0e8eefaec9bef2',
    redirect_uri:       'https://example-service.bbc.co.uk/callback',
    state:              '',
    created_at:       date,
    updated_at:       date
  }).complete(callback);
};

var initDatabase = function(done) {
  async.series([
    createClient,
    createDomain,
    createUser,
    createAuthorizationCode
  ], function(err) {
    if(err){
      done(new Error(JSON.stringify(err)));
      return;
    }
    done();
  });
};

var resetDatabase = function(done) {
  clearDatabase(function() {
    initDatabase(function() {
      done();
    });
  });
};

describe("POST /token", function() {
  before(function() {
    sinon.stub(generate, 'accessToken').returns('aed201ffb3362de42700a293bdebf694');
  });

  after(function() {
    generate.accessToken.restore();
  });

  context("when the client request an access token (webserver mode)", function() {
    context("and the authorization code is valid", function() {
      before(resetDatabase);

      before(function() {
        // Ensure pairing code has not expired
        var time = new Date("Wed Apr 09 2014 11:00:30 GMT+0100").getTime();
        this.clock = sinon.useFakeTimers(time, "Date");
      });

      after(function() {
        this.clock.restore();
      });

      context.skip("and the request doesn't specify any scope", function() {
        before(function(done) {
          var requestBody = {
            grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
            code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
            client_id:     100,
            redirect_uri:  'https://example-service.bbc.co.uk/callback'
          };

          requestHelper.sendRequest(this, '/token', {
            method: 'post',
            type:   'json',
            data:   requestBody
          }, done);
        });

        it("should return status 200", function() {
          expect(this.res.statusCode).to.equal(200);
        });

        it("should return a JSON object", function() {
          expect(this.res.headers['content-type']).to.equal('application/json; charset=utf-8');
          expect(this.res.body).to.be.an('object');
        });

        describe("the response body", function() {
          it("should include a valid access token", function() {
            expect(this.res.body).to.have.property('token');
            expect(this.res.body.token).to.equal('aed201ffb3362de42700a293bdebf694');
          });

          it("should include the token type", function() {
            expect(this.res.body).to.have.property('token_type');
            expect(this.res.body.token_type).to.equal('bearer');
          });

          it("should include a description", function() {
            expect(this.res.body).to.have.property('description');
            expect(this.res.body.description).to.equal('Test User at default scope');
          });

          it("should include a short description", function() {
            expect(this.res.body).to.have.property('short_description');
            expect(this.res.body.short_description).to.equal('default scope');
          });

          it("should include a valid refresh token"); // TODO: optional: refresh_token
          it("should include the lifetime of the access token"); // TODO: recommended: expires_in

        });
      });
    });

    context("with expired authorization code", function() {
      before(resetDatabase);

      before(function() {
        // The authorization code should expire 10 minutes after it was created
        var time = new Date("Wed Apr 09 2014 11:10:00 GMT+0100").getTime();
        this.clock = sinon.useFakeTimers(time, "Date");
      });

      after(function() {
        this.clock.restore();
      });

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          client_id:     100,
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an expired error", function() {
        assertions.verifyError(this.res, 400, 'expired');
      });
    });

    context("with missing authorization code", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          client_id:     100,
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_request error", function() {
        assertions.verifyError(this.res, 400, 'invalid_request');
      });
    });

    context("with incorrect authorization code", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          'invalid',
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          client_id:     100,
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_request error", function() {
        assertions.verifyError(this.res, 400, 'invalid_request');
      });
    });

    context("with incorrect content type", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          client_id:     100,
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'form',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_request error", function() {
        assertions.verifyError(this.res, 400, 'invalid_request');
      });
    });

    context("with incorrect grant_type", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'invalid',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          client_id:     100,
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an unsupported_grant_type error", function() {
        assertions.verifyError(this.res, 400, 'unsupported_grant_type');
      });
    });

    context("with missing client_id", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_request error", function() {
        assertions.verifyError(this.res, 400, 'invalid_request');
      });
    });

    context("with incorrect client_id", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          client_id:     99,
          redirect_uri:  'https://example-service.bbc.co.uk/callback',
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_client error", function() {
        assertions.verifyError(this.res, 400, 'invalid_client');
      });
    });

    context("with missing redirect_uri", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          client_id:     100,
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_request error", function() {
        assertions.verifyError(this.res, 400, 'invalid_request');
      });
    });

    context("with incorrect redirect_uri", function() {
      before(resetDatabase);

      before(function(done) {
        var requestBody = {
          grant_type:    'http://tech.ebu.ch/cpa/1.0/authorization_code',
          code:          '4e72e9fdd4bdc3892d0e8eefaec9bef2',
          redirect_uri:  'https://example-service.bbc.co.uk/wrong_callback',
          client_id:     100,
          domain:        'example-service.bbc.co.uk'
        };

        requestHelper.sendRequest(this, '/token', {
          method: 'post',
          type:   'json',
          data:   requestBody
        }, done);
      });

      it("should return an invalid_client error", function() {
        assertions.verifyError(this.res, 400, 'invalid_client');
      });
    });

    // TODO: Scope
  });
});
