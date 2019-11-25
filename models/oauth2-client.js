"use strict";

module.exports = function (sequelize, DataTypes) {
    var OAuth2Client = sequelize.define('OAuth2Client', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        client_id: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        client_secret: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        jwt_code: {
            type: DataTypes.STRING,
            allowNull: true
        },
        name: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        redirect_uri: { // TODO: Use its own table (RedirectURIWhiteList)
            type: DataTypes.STRING,
            allowNull: false
        },
        redirect_uri_2: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ''
        },
        redirect_uri_3: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ''
        },
        redirect_uri_4: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ''
        },
        redirect_uri_5: {
            type: DataTypes.STRING,
            allowNull: false,
            defaultValue: ''
        },
        use_template: {
            type: DataTypes.STRING,
            allowNull: true
        },
        email_redirect_uri: {
            type: DataTypes.STRING,
            allowNull: true
        }
    }, {
        underscored: true,

        associate: function (models) {
            OAuth2Client.hasMany(models.OAuth2AuthorizationCode);
            OAuth2Client.belongsTo(models.User);
        }
    });

    OAuth2Client.prototype.mayRedirect = function (uri) {
        if (this.redirect_uri === null) {
            return true;
        }
        if (!uri) {
            return true;
        }
        return uri.startsWith(this.redirect_uri);
    };

    OAuth2Client.prototype.mayEmailRedirect = function (uri) {
        if (!uri) {
            return true;
        }
        if (this.email_redirect_uri === null) {
            return false;
        }
        return uri.startsWith(this.email_redirect_uri);
    };

    return OAuth2Client;
};
