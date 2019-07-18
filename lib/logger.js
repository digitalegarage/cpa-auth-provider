"use strict";

var logger;

if (process.env.NODE_ENV === "test") {
    logger = require('./null-logger');
} else if (process.env.LOG_STYLE === 'BR') {
    var foo = require('@sep/br-logging');
    logger = new foo.Logger({
        name: 'br-sso',
        version: '1.0'
    });
    logger.info("BR logging started.");
} else {
    logger = require('./winston-logger');
}

module.exports = logger;
