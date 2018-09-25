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
                    // TODO fill userId with data.passport.user

                })
                .then(() => {
                    // TODO create index on userId
                })
                .catch((e) => {
                    reject(e);
                });
            }
            return resolve();
        });
    },
    down: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            // TODO remove index
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
