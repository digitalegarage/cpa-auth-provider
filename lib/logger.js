"use strict";

var logger;

if (process.env.NODE_ENV === "test") {
    logger = require('./null-logger');
} else if (process.env.LOG_STYLE === 'BR') {
    var brlogger = require('@sep/br-logging');
    logger = new brlogger.Logger({
        name: 'ebu-sso',
        version: '1'
    });
    logger.info("BR logging set up");
} else {
    logger = require('./winston-logger');
}

module.exports = logger;
