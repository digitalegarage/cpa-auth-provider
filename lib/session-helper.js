/* jslint node:true, esversion:6 */
"use strict";

const
    Op = require('sequelize').Op,
    _ = require('underscore'),
    SqlString = require('sqlstring'),
    db = require('../models');

var handleSequelizeStore = (SequelizeStore, session) => {
    // Do not use arrow functions here. It will mess up.
    SequelizeStore.prototype.deleteByUserId = function (userId, excludeSid, fn) {
        userId = parseInt(userId);
        if (isNaN(userId))
            fn("ID is not a number.",null);
        else {
            var db = this.sessionModel;
            db.count({where: { userId: ""+userId }})
            .then(function(count) {
                if (count === 0) {
                    fn(null,true);
                } else {
                    if (excludeSid && excludeSid !== null) {
                        db.findAll({where: { userId: ""+userId, sid: { [Op.ne]: excludeSid }}})
                        .then(function(results) {
                            // a resolving destroy() doesn't guarantee a deleted record.
                            _.each(results,function(r) { r.destroy(); });
                            // so we return without being sure the records are gone
                            fn(null,true);
                        })
                        .catch(function(err) {
                            fn(err,null);
                        });
                    } else {
                        db.findAll({where: {userId: ""+userId}})
                        .then(function(results) {
                            _.each(results,function(r) { r.destroy(); });
                            fn(null,true);
                        })
                        .catch(function(err) {
                            fn(err,null);
                        });
                    }
                }
            })
            .catch(function(err) {
                console.log(err);
                fn(err,null);
            });
        }
    };
    return;
};

var handleSqliteStore = (SQLiteStore, session) => {
    SQLiteStore.prototype.deleteByUserId = function (userId, excludeSid, fn) {
        var db = this.db;
        var table = this.table;
        userId = parseInt(userId);
        if (isNaN(userId))
            fn("ID is not a number.",null);
        else {
            var countQuery =  SqlString.format('SELECT COUNT (*) AS COUNT FROM ' + table + '  WHERE json_extract(sess, \'$.passport.user\') = ' + userId);
            var deleteQuery = SqlString.format('DELETE FROM ' + table + ' WHERE json_extract(sess, \'$.passport.user\') = ' + userId);
            if (excludeSid && excludeSid !== null)
                deleteQuery = SqlString.format('DELETE FROM ' + table + ' WHERE json_extract(sess, \'$.passport.user\') = ' + userId + '  AND sid != ?', [excludeSid]);
            db.all(countQuery, function(err,result) {
                if (err) {
                    fn(err,null);
                } else if (result[0] === undefined || result[0].COUNT === 0) {
                    fn(null,true);
                } else {
                    db.run(deleteQuery, function(err, result) {
                        if (err)
                            fn(err);
                        else
                            fn(null, true);
                    });
                }
            });
        }
    };
};

module.exports = {
    handleSqliteStore: handleSqliteStore,
    handleSequelizeStore: handleSequelizeStore
};
