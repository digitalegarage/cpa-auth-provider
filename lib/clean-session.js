"use strict";
var db = require('../models');
var config = require('../config');
const logger = require('./logger');
const appHelper = require('../lib/app-helper');
const Op = db.sequelize.Op;

module.exports = {
    start: start,
};

function cycle() {

    // Clean session
    appHelper.destroyNotLoggedSessions(logger);

    setTimeout(
        cycle,
        60 * 60 * 24 * 1000
    );
}

function start() {
    if (config.session && config.session.clean) {
        cycle();
    }
}
