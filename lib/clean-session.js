"use strict";
var db = require('../models');
var config = require('../config');
const logger = require('./logger');
const appHelper = require('../lib/app-helper');
const Cron = require('cron').CronJob;

module.exports = {
    start: start,
};


function start() {
    if (config.session && config.session.clean) {
        return new Cron('0 0 2 * * *', () => {
            logger.info("Cron clean session table");
            appHelper.destroyNotLoggedSessions(logger);
        }, null, true, 'Europe/Berlin');
    }
}
