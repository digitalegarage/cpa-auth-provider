/* jslint node:true, esversion:6 */
'use strict';

module.exports = {
    up: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            if (process.env.DB_TYPE === 'sqlite')
                resolve();
            else {
                queryInterface.addColumn('Sessions','userId',{type: Sequelize.STRING, allowNull: true})
                .then(() => {
                    return queryInterface.sequelize.query('update public."Sessions" set "userId" = data::json->\'passport\'->\'user\'')
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
