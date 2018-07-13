"use strict";

var cors = require('cors');

var config = require('../config');

var logger = require('./logger');

module.exports = cors({
    origin: function (origin, callback) {
      if (origin) {
        var wildcardDomains = config.cors.wildcard_domains;
        var isAllowed = config.cors.allowed_domains.indexOf(origin.toLowerCase()) !== -1;
        if (wildcardDomains && !isAllowed) {
          for (var i = 0; i < wildcardDomains.length; i++) {
            if (origin.toLowerCase().endsWith(wildcardDomains[i])) {
              isAllowed = true;
              break;
            }
          }
        }
        logger.debug("Origin is " + origin + " Allowed domains: " + config.cors.allowed_domains + " " + config.cors.wildcard_domains + " isAllowed " + isAllowed);
        callback(null, isAllowed ? origin : false);
      } else {
        logger.debug("CORS called without origin header");
        callback(null,false);
      }
    },
    methods: 'POST,GET', // 'GET,PUT,POST,DELETE,OPTIONS'
    credentials: true,
    allowedHeaders: 'Content-Type,Authorization,Content-Length,X-Requested-With'
});
