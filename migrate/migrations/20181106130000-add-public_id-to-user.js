/* jslint node:true, esversion:6 */
'use strict';

const uuid = require('uuid/v4');

module.exports = {
    up: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            if (process.env.DB_TYPE === 'sqlite')
                resolve();
            else {
                queryInterface.sequelize.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
                .then(() => {
                    queryInterface.addColumn('Users','public_uid',{type: Sequelize.UUID, defaultValue: Sequelize.literal('uuid_generate_v4()'), allowNull: false})
                    .then(() => {
                        queryInterface.sequelize.query('CREATE INDEX Users_publicuid_idx ON public."Users" ("public_uid");');
                        resolve();
                    })
                    .catch((e) => {
                        reject(e);
                    });
                });
            }
        });
    },
    down: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            queryInterface.removeColumn('Users','public_uid')
            .then(() => {
                return resolve();
            })
            .catch((e) => {
                reject(e);
            });
        });
    }
};
