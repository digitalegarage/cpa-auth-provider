"use strict";

var bcrypt = require('bcrypt');
var config = require('../config');


module.exports = function (sequelize, DataTypes) {

    var User = sequelize.define('User', {
        id: {type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true},
        tracking_uid: DataTypes.STRING,
        provider_uid: DataTypes.STRING,
        email: {type: DataTypes.STRING, unique: true},
        password: DataTypes.STRING,
        enable_sso: DataTypes.BOOLEAN,
        display_name: DataTypes.STRING,
        photo_url: DataTypes.STRING,
        verified: DataTypes.BOOLEAN,
        password_changed_at: DataTypes.BIGINT,
        last_login_at: DataTypes.BIGINT
    }, {
        underscored: true,
        instanceMethods: {
            logLogin: function (transaction) {
                var self = this;
                return self.updateAttributes({last_login_at: Date.now()}, {transaction: transaction});
            },
            setPassword: function (password) {
                var self = this;
                return new Promise(
                    function (resolve, reject) {
                        bcrypt.hash(password, 10).then(
                            function (hash) {
                                return self.updateAttributes(
                                    {password: hash, password_changed_at: Date.now()}
                                )
                            }
                        ).then(
                            resolve
                        ).catch(reject);
                    }
                );
            },
            verifyPassword: function (password) {
                return bcrypt.compare(password, this.password);
            },
            isFacebookUser: function () {
                var self = this;
                if(self.provider_uid && self.provider_uid.indexOf('fb:') !== -1) {
                    return true;
                }
                return false;
            }
        },
        associate: function (models) {
            User.hasMany(models.Client);
            User.hasMany(models.AccessToken);
            User.hasMany(models.ValidationCode);
            User.belongsTo(models.IdentityProvider);
            User.belongsTo(models.Permission);
            User.hasOne(models.UserProfile);
        }
    });

    return User;
};