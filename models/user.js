"use strict";
var dateFormat = require('dateformat');

module.exports = function (sequelize, DataTypes) {
    var User = sequelize.define('User', {
        id: {type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true},
        tracking_uid: DataTypes.STRING,
        enable_sso: DataTypes.BOOLEAN,
        display_name: DataTypes.STRING,
        photo_url: DataTypes.STRING,
        firstname: DataTypes.STRING,
        lastname: DataTypes.STRING,
        gender: DataTypes.STRING,
        /*
        @deprecated use date_of_birth_ymd
         */
        date_of_birth: DataTypes.BIGINT,
        date_of_birth_ymd: DataTypes.DATEONLY,
        language: DataTypes.STRING,
        last_seen: DataTypes.BIGINT,
        scheduled_for_deletion_at: DataTypes.DATE,
        public_uid: {
            type: DataTypes.UUID,
            defaultValue: DataTypes.UUIDV4
        }

    }, {
        underscored: true,

        associate: function (models) {
            User.hasMany(models.Client);
            User.hasMany(models.AccessToken);
            User.hasMany(models.ValidationCode);
            User.hasMany(models.SocialLogin);
            User.hasOne(models.LocalLogin);
            User.belongsTo(models.IdentityProvider);
            User.belongsTo(models.Permission);
        }
    });


    User.prototype.getDisplayName = function (policy, defaultDisplayName) {
        if (defaultDisplayName && defaultDisplayName.match(/^\s*$/)) {
            return (this.LocalLogin && this.LocalLogin.login) ? this.LocalLogin.login : '';
        }
        if (!policy) {
            return defaultDisplayName;
        }
        if (policy === "FIRSTNAME") {
            if (this.firstname) {
                return this.firstname;
            }
        }
        if (policy === "LASTNAME") {
            if (this.lastname) {
                return this.lastname;
            }
        }
        if (policy === "FIRSTNAME_LASTNAME") {
            if (this.firstname && this.lastname) {
                return this.firstname + ' ' + this.lastname;
            }
        }
        return defaultDisplayName;
    };

    User.prototype.logLastSeen = function () {
        return this.updateAttributes({last_seen: Date.now()});
    };

    User.prototype.isScheduledForDeletion = function () {
        return !!this.scheduled_for_deletion_at;
    };

    return User;
};
