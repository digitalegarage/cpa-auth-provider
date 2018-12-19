/* jslint node:true, esversion:6 */
'use strict';

var uuid = require('uuid/v4');
var db = require('../../models');
var _ = require('underscore');
var Op = require('sequelize').Op;

module.exports = {
    up: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            if (process.env.DB_TYPE === 'sqlite'){
                queryInterface.addColumn('Users', 'public_uid', {type: Sequelize.STRING, defaultValue: Sequelize.UUIDV4, allowNull: true}).then(() => {
                    db.User.findAll()
                    .then(function(users) {
                        _.each(users,function(u) {
                            db.User.update({public_uid: uuid()}, {where: {'id': u.id}})
                            .then(function(update) {
                                // Do we need to care about "done"?
                            });
                        });
                    });
                });
            } else if (process.env.DB_TYPE === 'postgres') {
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
                })
                .catch((e) => {
                    reject(e);
                });
            } else if (process.env.DB_TYPE === 'mysql') {
                queryInterface.addColumn('Users','public_uid',{type: Sequelize.UUID, defaultValue: Sequelize.UUIDV4, allowNull:false})
                .then(() => {
                    queryInterface.sequelize.query('UPDATE Users SET public_uid = (SELECT UUID()) WHERE public_uid is null OR public_uid = ""')
                    .then(() => {
                        queryInterface.sequelize.query('CREATE UNIQUE INDEX users_publicUid_idx on Users (public_uid)')
                        .then(() => {
                            resolve();
                        });
                    });
                });
            } else {
                // WTF?
                reject();
            }
        });
    },
    down: function(queryInterface,Sequelize) {
        return new Promise((resolve,reject) => {
            queryInterface.removeColumn('Users','public_uid')
            .then(() => {
                queryInterface.sequelize.query('ALTER TABLE Users DROP INDEX users.publicUid_idx')
                .then(() => {
                    return resolve();
                })
                .catch(() => {
                    // ignore.
                    return resolve();
                });
            })
            .catch((e) => {
                reject(e);
            });
        });
    }
};