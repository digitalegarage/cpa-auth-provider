"use strict";

module.exports = function (sequelize, DataTypes) {
    var Client = sequelize.define('Client', {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true
        },
        secret: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        name: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        software_id: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        software_version: {
            type: DataTypes.STRING,
            validate: {
                notEmpty: true
            }
        },
        ip: {
            type: DataTypes.STRING,
            validate: {
                isIP: true
            }
        },
        registration_type: {
            type: DataTypes.ENUM,
            values: ['dynamic', 'static'],
            defaultValue: 'dynamic',
            validate: {
                notEmpty: true
            }
        },
        redirect_uri: { //TODO: Move to its own table
            type: DataTypes.STRING,
            allowNull: true
        },
        redirect_uri_2: {
            type: DataTypes.STRING,
            allowNull: true,
            defaultValue: ''
        },
        redirect_uri_3: {
            type: DataTypes.STRING,
            allowNull: true,
            defaultValue: ''
        },
        redirect_uri_4: {
            type: DataTypes.STRING,
            allowNull: true,
            defaultValue: ''
        },
        redirect_uri_5: {
            type: DataTypes.STRING,
            allowNull: true,
            defaultValue: ''
        }
    }, {
        underscored: true,

        associate: function (models) {
            Client.hasMany(models.PairingCode);
            Client.hasMany(models.AccessToken);
            Client.belongsTo(models.User);
        }
    });

    return Client;
};
