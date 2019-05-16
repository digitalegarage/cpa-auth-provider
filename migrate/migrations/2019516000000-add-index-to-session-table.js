/* jslint node:true, esversion:6 */
'use strict';

module.exports = {
    up: function(queryInterface, Sequelize) {
        return new Promise((resolve, reject) => {
            if (process.env.DB_TYPE === 'sqlite')
                resolve();
            else {
                return queryInterface.sequelize.query('SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = \'Sessions\')')
                .then((res) => {
                    if (res && res.length && res[0].length === 1) {
                        // There is a "Sessions" table.
                        console.log('There is a "Sessions" table.');
                        return queryInterface.sequelize.query('SELECT DISTINCT \'Sessions\', \'sessions_expire_idx\' FROM INFORMATION_SCHEMA.STATISTICS')
                        .then((res) => {
                            if (res && res.length && res[0].length === 1) {
                                // Index "sessions_expire_idx" already exists.
                                console.log('Index "sessions_expire_idx" already exists.');
                                resolve();
                            } else {
                                // Index "sessions_expire_idx" doesn't exist => create it.
                                console.log('Index "sessions_expire_idx" doesn\'t exist => create it.');
                                return queryInterface.sequelize.query('CREATE INDEX \'sessions_expire_idx\' ON \'Sessions\' ("sid");')
                                .then(() => {
                                    resolve();
                                }).catch((e) => {
                                    reject(e);
                                });
                            }
                        }).catch((e) => {
                            reject(e);
                        });
                    } else {
                        // There is no "Sessions" table, so no altering. Sequelize will create dynamically.
                        console.log('There is no "Sessions" table, so no altering. Sequelize will create dynamically.');
                        resolve();
                    }
                }).catch((e) => {
                    console.console.error(e);
                });
            }
        });
    },
    down: function(queryInterface, Sequelize) {
        return new Promise((resolve, reject) => {
            // nothing (I don't see the point of trying to remove the index...)
        });
    }
};
