"use strict";
var dateFormat = require('dateformat');


module.exports = function (sequelize, DataTypes) {

    var SocialLogin = sequelize.define('SocialLogin', {
        name: DataTypes.STRING,
        uid: DataTypes.STRING,
        email: DataTypes.STRING,
        firstname: DataTypes.STRING,
        lastname: DataTypes.STRING,
        gender: DataTypes.STRING,
        /*
        @deprecated use date_of_birth_ymd
         */
        date_of_birth: DataTypes.BIGINT,
        date_of_birth_ymd: DataTypes.DATEONLY,
        language: DataTypes.STRING,
        last_login_at: DataTypes.BIGINT
    }, {
        underscored: true,
        // Due to a bug on sequelize, unique constraint are not created on the database.
        // https://github.com/sequelize/cli/issues/272#issuecomment-194754086
        // So use an index
        indexes: [
            {
                unique: true,
                fields: ["user_id", "name"]
            }
        ],
        uniqueKeys: {
            // Due to a bug on sequelize, unique constraint are not created on the database.
            // https://github.com/sequelize/cli/issues/272#issuecomment-194754086
            // So use an index
            // uniqueKeys: {
            //     actions_unique: {
            //         fields:["user_id", "name"]
            //     }
            // }
        },
        associate: function (models) {
            SocialLogin.belongsTo(models.User, {onDelete: 'cascade'});
        }
    });

    SocialLogin.prototype.logLogin = function (user, transaction) {
        var self = this;
        return self.updateAttributes({last_login_at: Date.now()}, {transaction: transaction}).then(function () {
            return user.logLastSeen();
        });
    };

    SocialLogin.prototype.getProfile = function(){
        return {
            user: {
                id: this.user_id,
                    email: this.email,
                    email_verified: true,
                    display_name: this.display_name ? this.display_name : this.email,
                    firstname: this.firstname,
                    lastname: this.lastname,
                    gender: this.gender,
                    date_of_birth: this.date_of_birth_ymd ? dateFormat(this.date_of_birth_ymd, "yyyy-mm-dd") : null,
            }
        };
    };

    return SocialLogin;
};