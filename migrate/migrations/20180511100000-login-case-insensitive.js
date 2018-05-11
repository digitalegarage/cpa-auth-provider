'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        if (process.env.DB_TYPE !== 'postgres') {
            return resolve();
        }
        return queryInterface.removeConstraint('LocalLogins', 'LocalLogins_login_key')
            .then(function () {
                return queryInterface.sequelize.query('﻿CREATE UNIQUE INDEX LocalLogins_login_idx ON public."LocalLogins" (UPPER(login));');
            });
    },

    down: function (queryInterface, Sequelize) {
        return resolve();
    }

};
