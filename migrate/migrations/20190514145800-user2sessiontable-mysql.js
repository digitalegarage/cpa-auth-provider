/* jslint node:true, esversion:6 */
'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        return new Promise((resolve, reject) => {
            if (process.env.DB_TYPE !== 'mysql')
                resolve();
            else {
                // check if Table "Sessions" is present
//                queryInterface.sequelize.query('SHOW TABLES LIKE \'Sessions\'')
//                .then((result,meta) => {
//                    if (result && result.length && result[0].length === 0) {
//                        // NOP. Table doesn't exist, let sequelize create it. This will contain userId, so no need to update here.
//                        resolve();
//                    } else {
//                        queryInterface.sequelize.query('SELECT * from information_schema.COLUMNS WHERE TABLE_NAME = \'Sessions\' AND COLUMN_NAME = \'userId\'')
//                        .then(r => {
//                            if (r[0].length === 0) {
//                                // column userId does not exist. Create:
//                                queryInterface.addColumn('Sessions', 'userId', {type: Sequelize.STRING(255)})
//                                .then(() => {
//                                    // update userId column with data from session/passport
//                                    queryInterface.sequelize.query('UPDATE Sessions set userId = JSON_EXTRACT(`data`, \'$.passport.user\')')
//                                    .then(() => {
//                                        resolve();
//                                    })
//                                });
//                            } else {
//                                // column userId exists. Fill it. Dup because of async row creation.
//                                queryInterface.sequelize.query('UPDATE Sessions set userId = JSON_EXTRACT(`data`, \'$.passport.user\')')
//                                .then(() => {
//                                    resolve();
//                                });
//                            }
//                        });
//                    }
//                })
//                .catch(e => {
//                    reject(e);
//                });
                resolve();
            }
        });
    },
    down: function (queryInterface, Sequelize) {
        return new Promise((resolve,reject) => {
            // only remove if we're on mysql. Other DBs are handled in another migration.
            if (process.env.DB_TYPE !== 'mysql')
                resolve();
            else {
                queryInterface.removeColumn('Sessions', 'userId')
                .then(() => {
                    resolve();
                })
                .catch(e => {
                    reject(e);
                });
            }
        });
    }
};
