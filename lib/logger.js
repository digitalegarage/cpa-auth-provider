"use strict";

var logger;

if (process.env.NODE_ENV === "test") {
    logger = require('./null-logger');
} else if (process.env.LOG_STYLE === 'BR') {
    // Here comes the br-logging
} else {
    logger = require('./winston-logger');
}

module.exports = logger;
