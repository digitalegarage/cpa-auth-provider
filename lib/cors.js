"use strict";

var cors = require('cors');

var config = require('../config');

var logger = require('./logger');

module.exports = cors({
    origin: function (origin, callback) {
        var isWildcard = config.cors.use_wildcard_domain;
        var isAllowed = false;
        if (isWildcard) {
          var wildcardDomain = config.cors.wildcard_domain;
          if (wildcardDomain) {
            isAllowed = origin.endsWith(wildcardDomain);
            logger.debug("Origin is " + origin + ", using wildcard_domain " + wildcardDomain + ": isAllowed " + isAllowed);
          } else {
            logger.error("You set use_wildcard_domain, but no wildcard_domain was given!");
          }
        } else {
          isAllowed = config.cors.allowed_domains.indexOf(origin) !== -1;
          logger.debug("Origin is " + origin + " Allowed domains (" + config.cors.allowed_domains.length + "): " + config.cors.allowed_domains + " isAllowed " + isAllowed);
        }
        callback(null, isAllowed ? origin : false);
    },
    methods: 'POST,GET', // 'GET,PUT,POST,DELETE,OPTIONS'
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization,Content-Length,X-Requested-With'
});
