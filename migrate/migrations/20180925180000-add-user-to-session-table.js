/* jslint node:true, esversion:6 */
'use strict';

module.exports = {
    up: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            if (process.env.DB_TYPE === 'sqlite')
                resolve();
            else {
                queryInterface.sequelize.query('SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = \'Sessions\')')
                .then((res) => {
                    if (res[0][0].exists === true) {
                        queryInterface.addColumn('Sessions','userId',{type: Sequelize.STRING, allowNull: true})
                        .then(() => {
                            return queryInterface.sequelize.query('update public."Sessions" set "userId" = data::json->\'passport\'->\'user\' where data::json->\'passport\' is not null')
                            .then(function(rows) {
                                return;
                            })
                            .catch(function(e) {
                                reject(e);
                            });
                        })
                        .then(() => {
                            queryInterface.sequelize.query('﻿CREATE INDEX Sessions_userid_idx ON public."Sessions" ("userId");');
                            resolve();
                        })
                        .catch((e) => {
                            reject(e);
                        });
                    } else {
                        // There is no "Sessions" table, so no altering. Sequelize will create dynamically.
                        resolve();
                    }
                })
                .catch((e) => {
                    console.console.error(e);
                });
            }
        });
    },
    down: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            // TODO remove index?
            queryInterface.removeColumn('Sessions','userId')
            .then(() => {
                return resolve();
            })
            .catch((e) => {
                reject(e);
            });
        });
    }
};
