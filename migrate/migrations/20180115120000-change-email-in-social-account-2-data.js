'use strict';

var util = require('util');

//SQL Magic (POSTGRES) query to be able to run that migration file as much as you want :)
// ﻿DELETE FROM public."SequelizeMeta" WHERE name='20180115120000-change-email-in-social-account-2-data.js';
// ﻿DELETE FROM public."LocalLogins";


function getSQLDateFormated(date) {
    return date.getUTCFullYear() + "-" +
        ("00" + (date.getUTCMonth() + 1)).slice(-2) + "-" +
        ("00" + date.getUTCDate()).slice(-2) + " " +
        ("00" + date.getUTCHours()).slice(-2) + ":" +
        ("00" + date.getUTCMinutes()).slice(-2) + ":" +
        ("00" + date.getUTCSeconds()).slice(-2);
}

function getUserSelectQuery() {
    if (process.env.DB_TYPE === "postgres") {
        return "select * from \"public\".\"Users\"";
    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
}

function getUserProfileSelectQuery() {
    if (process.env.DB_TYPE === "postgres") {
        return "select * from \"public\".\"UserProfiles\"";
    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
}

function getUsersSelectQueryNbOfResult(users) {
    if (process.env.DB_TYPE === "postgres") {
        return users[0].length; //TODO test if no user
    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
}

function getUserProfilesSelectQueryNbOfResult(userProfiles) {
    if (process.env.DB_TYPE === "postgres") {
        return userProfiles[0].length; //TODO test if no user
    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
}

function buildInsertQuery(user) {

    var login = user.email;
    var password = user.password;
    var verified = user.verified ? true : false;
    var password_changed_at = user.password_changed_at;
    var last_login_at = user.last_login_at;
    var user_id = user.id;
    var created_at = getSQLDateFormated(user.created_at);
    var updated_at = getSQLDateFormated(user.updated_at);

    // We assume that there are no social login to migrate.
    // That's the case at RTS : we have social login but they are migrated from openAM to the idp as local account
    // BR is not supposed to have social login
    if (process.env.DB_TYPE === "postgres") {

        console.log("user login: " + login);
        console.log("user password: " + password);
        console.log("user verified: " + verified);
        console.log("user password_changed_at: " + password_changed_at);
        console.log("user last_login_at: " + last_login_at);
        console.log("user user_id: " + user_id);
        console.log("user created_at: " + created_at);
        console.log("user updated_at: " + updated_at);

        return "insert into \"public\".\"LocalLogins\" (login, password, verified, password_changed_at, last_login_at, user_id, created_at, updated_at) " +
            " VALUES ('" + login + "', '" + password + "', '" + verified + "', '" + password_changed_at + "', '" + last_login_at + "', '" + user_id + "', '" + created_at + "', '" + updated_at + "')";
    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
}

function buildUpdateQueries(userProfile) {
    var fieldsToUpdates = [];
    var updateQuery;
    var userId = userProfile.user_id;

    if (process.env.DB_TYPE === "postgres") {
        updateQuery = "update \"public\".\"Users\" set %s =  '%s' where id = " + userId;

    } else {
        //TODO support mysql
        throw new Error(process.env.DB_TYPE + " database is not supported now :'(");
    }
    if (userProfile.firstname) {
        fieldsToUpdates.push(util.format(updateQuery, "firstname", userProfile.firstname));
    }
    if (userProfile.lastname) {
        fieldsToUpdates.push(util.format(updateQuery, "lastname", userProfile.lastname));
    }
    if (userProfile.gender) {
        fieldsToUpdates.push(util.format(updateQuery, "gender", userProfile.gender));
    }
    if (userProfile.date_of_birth) {
        fieldsToUpdates.push(util.format(updateQuery, "date_of_birth", userProfile.date_of_birth));
    }
    if (userProfile.language) {
        fieldsToUpdates.push(util.format(updateQuery, "language", userProfile.language));
    }
    return fieldsToUpdates;

}


module.exports = {
    up: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            //FIXME POSTGRES specific use process.env.DB_TYPE to see if current run use postgres (RTS) or mysql(BR). For other Database don't do anything and CRASH
            return queryInterface.sequelize.query(getUserSelectQuery()).then(function (users) {
                var batch = [];
                // insert data in appropriate table
                let nb = getUsersSelectQueryNbOfResult(users);
                for (var i = 0; i < nb; i++) {
                    console.log("Migrating local login " + (i + 1) + " of " + nb);
                    batch.push(queryInterface.sequelize.query(buildInsertQuery(users[0][i])));
                }

                return Promise.all(batch);
            }).then(function () {
                console.log("now migrating user profile...");
                return queryInterface.sequelize.query(getUserProfileSelectQuery());
            }).then(function (userProfiles) {
                var batch = [];
                // insert data in appropriate table
                let nb = getUserProfilesSelectQueryNbOfResult(userProfiles);
                for (var i = 0; i < nb; i++) {
                    console.log("Migrating user profile " + (i + 1) + " of " + nb + "...");
                    var updateQueries = buildUpdateQueries(userProfiles[0][i]);
                    for (var j = 0; j < updateQueries.length; j++) {
                        console.log("updateQueries[" + j + "]:", updateQueries[j]);
                        batch.push(queryInterface.sequelize.query(updateQueries[j]));
                    }
                }
                return Promise.all(batch);
                //TODO
                // Drop column

                // Drop table user profile

            }).then(resolve).catch(reject);
        });
    },

    down: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            resolve();
        });
    }
}
