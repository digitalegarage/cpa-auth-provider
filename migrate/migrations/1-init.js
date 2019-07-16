'use strict';

var Sequelize = require('sequelize');

/**
 * Actions summary:
 *
 * createTable "Domains", deps: []
 * createTable "IdentityProviders", deps: []
 * createTable "Permissions", deps: []
 * createTable "Users", deps: [IdentityProviders, Permissions]
 * createTable "Clients", deps: [Users]
 * createTable "LocalLogins", deps: [Users]
 * createTable "OAuth2Clients", deps: [Users]
 * createTable "OAuth2AuthorizationCodes", deps: [OAuth2Clients, Users, OAuth2Clients]
 * createTable "OAuth2RefreshTokens", deps: [Users, OAuth2Clients]
 * createTable "AccessTokens", deps: [Clients, Domains, Users]
 * createTable "PairingCodes", deps: [Clients, Domains, Users]
 * createTable "ValidationCodes", deps: [Users]
 * createTable "SocialLogins", deps: [Users]
 * createTable "UserEmailTokens", deps: [Users, OAuth2Clients]
 * addIndex ["user_id","name"] to table "SocialLogins"
 * addIndex ["key"] to table "OAuth2RefreshTokens"
 *
 **/

var info = {
    "revision": 1,
    "name": "init",
    "created": "2019-06-20T08:30:16.356Z",
    "comment": ""
};

var migrationCommands = [{
        fn: "createTable",
        params: [
            "Domains",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "name": {
                    "type": Sequelize.STRING,
                    "field": "name",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "display_name": {
                    "type": Sequelize.STRING,
                    "field": "display_name",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "access_token": {
                    "type": Sequelize.STRING,
                    "field": "access_token",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "IdentityProviders",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "name": {
                    "type": Sequelize.STRING,
                    "field": "name"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "Permissions",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "label": {
                    "type": Sequelize.STRING,
                    "field": "label",
                    "unique": true
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "Users",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "tracking_uid": {
                    "type": Sequelize.STRING,
                    "field": "tracking_uid"
                },
                "enable_sso": {
                    "type": Sequelize.BOOLEAN,
                    "field": "enable_sso"
                },
                "display_name": {
                    "type": Sequelize.STRING,
                    "field": "display_name"
                },
                "photo_url": {
                    "type": Sequelize.STRING,
                    "field": "photo_url"
                },
                "firstname": {
                    "type": Sequelize.STRING,
                    "field": "firstname"
                },
                "lastname": {
                    "type": Sequelize.STRING,
                    "field": "lastname"
                },
                "gender": {
                    "type": Sequelize.STRING,
                    "field": "gender"
                },
                "date_of_birth": {
                    "type": Sequelize.BIGINT,
                    "field": "date_of_birth"
                },
                "date_of_birth_ymd": {
                    "type": Sequelize.DATEONLY,
                    "field": "date_of_birth_ymd"
                },
                "language": {
                    "type": Sequelize.STRING,
                    "field": "language"
                },
                "last_seen": {
                    "type": Sequelize.BIGINT,
                    "field": "last_seen"
                },
                "scheduled_for_deletion_at": {
                    "type": Sequelize.DATE,
                    "field": "scheduled_for_deletion_at"
                },
                "public_uid": {
                    "type": Sequelize.UUID,
                    "field": "public_uid",
                    "defaultValue": Sequelize.UUIDV4
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "identity_provider_id": {
                    "type": Sequelize.INTEGER,
                    "field": "identity_provider_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "IdentityProviders",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "permission_id": {
                    "type": Sequelize.INTEGER,
                    "field": "permission_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Permissions",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "Clients",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "secret": {
                    "type": Sequelize.STRING,
                    "field": "secret",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "name": {
                    "type": Sequelize.STRING,
                    "field": "name",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "software_id": {
                    "type": Sequelize.STRING,
                    "field": "software_id",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "software_version": {
                    "type": Sequelize.STRING,
                    "field": "software_version",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "ip": {
                    "type": Sequelize.STRING,
                    "field": "ip",
                    "validate": {
                        "isIP": true
                    }
                },
                "registration_type": {
                    "type": Sequelize.ENUM('dynamic', 'static'),
                    "field": "registration_type",
                    "validate": {
                        "notEmpty": true
                    },
                    "defaultValue": "dynamic"
                },
                "redirect_uri": {
                    "type": Sequelize.STRING,
                    "field": "redirect_uri",
                    "allowNull": true
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "LocalLogins",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true,
                    "allowNull": false
                },
                "login": {
                    "type": Sequelize.STRING,
                    "field": "login",
                    "unique": true
                },
                "password": {
                    "type": Sequelize.STRING,
                    "field": "password"
                },
                "verified": {
                    "type": Sequelize.BOOLEAN,
                    "field": "verified"
                },
                "password_changed_at": {
                    "type": Sequelize.BIGINT,
                    "field": "password_changed_at"
                },
                "last_login_at": {
                    "type": Sequelize.BIGINT,
                    "field": "last_login_at"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "OAuth2Clients",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "client_id": {
                    "type": Sequelize.STRING,
                    "field": "client_id",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "client_secret": {
                    "type": Sequelize.STRING,
                    "field": "client_secret",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "jwt_code": {
                    "type": Sequelize.STRING,
                    "field": "jwt_code",
                    "allowNull": true
                },
                "name": {
                    "type": Sequelize.STRING,
                    "field": "name",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "redirect_uri": {
                    "type": Sequelize.STRING,
                    "field": "redirect_uri",
                    "allowNull": false
                },
                "use_template": {
                    "type": Sequelize.STRING,
                    "field": "use_template",
                    "allowNull": true
                },
                "email_redirect_uri": {
                    "type": Sequelize.STRING,
                    "field": "email_redirect_uri",
                    "allowNull": true
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "OAuth2AuthorizationCodes",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "authorization_code": {
                    "type": Sequelize.STRING,
                    "field": "authorization_code"
                },
                "redirect_uri": {
                    "type": Sequelize.STRING,
                    "field": "redirect_uri"
                },
                "state": {
                    "type": Sequelize.STRING,
                    "field": "state"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "oauth2_client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "oauth2_client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "OAuth2Clients",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "o_auth2_client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "o_auth2_client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "OAuth2Clients",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "OAuth2RefreshTokens",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "key": {
                    "type": Sequelize.STRING,
                    "field": "key",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "expires_at": {
                    "type": Sequelize.BIGINT,
                    "field": "expires_at",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "scope": {
                    "type": Sequelize.STRING,
                    "field": "scope"
                },
                "consumed": {
                    "type": Sequelize.BOOLEAN,
                    "field": "consumed"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "oauth2_client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "oauth2_client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "OAuth2Clients",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "AccessTokens",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "token": {
                    "type": Sequelize.STRING,
                    "field": "token",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Clients",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "domain_id": {
                    "type": Sequelize.INTEGER,
                    "field": "domain_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Domains",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "PairingCodes",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "device_code": {
                    "type": Sequelize.STRING,
                    "field": "device_code"
                },
                "user_code": {
                    "type": Sequelize.STRING,
                    "field": "user_code"
                },
                "verification_uri": {
                    "type": Sequelize.STRING,
                    "field": "verification_uri"
                },
                "state": {
                    "type": Sequelize.ENUM('pending', 'verified', 'denied'),
                    "field": "state",
                    "validate": {
                        "notEmpty": true
                    },
                    "defaultValue": "pending"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Clients",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "domain_id": {
                    "type": Sequelize.INTEGER,
                    "field": "domain_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Domains",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "ValidationCodes",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "date": {
                    "type": Sequelize.BIGINT,
                    "field": "date",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "value": {
                    "type": Sequelize.STRING,
                    "field": "value",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "type": {
                    "type": Sequelize.ENUM('email', 'account'),
                    "field": "type",
                    "validate": {
                        "notEmpty": true
                    },
                    "defaultValue": "email"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "SocialLogins",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "field": "id",
                    "autoIncrement": true,
                    "primaryKey": true,
                    "allowNull": false
                },
                "name": {
                    "type": Sequelize.STRING,
                    "field": "name"
                },
                "uid": {
                    "type": Sequelize.STRING,
                    "field": "uid"
                },
                "email": {
                    "type": Sequelize.STRING,
                    "field": "email"
                },
                "firstname": {
                    "type": Sequelize.STRING,
                    "field": "firstname"
                },
                "lastname": {
                    "type": Sequelize.STRING,
                    "field": "lastname"
                },
                "gender": {
                    "type": Sequelize.STRING,
                    "field": "gender"
                },
                "date_of_birth": {
                    "type": Sequelize.BIGINT,
                    "field": "date_of_birth"
                },
                "date_of_birth_ymd": {
                    "type": Sequelize.DATEONLY,
                    "field": "date_of_birth_ymd"
                },
                "language": {
                    "type": Sequelize.STRING,
                    "field": "language"
                },
                "last_login_at": {
                    "type": Sequelize.BIGINT,
                    "field": "last_login_at"
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "cascade",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "UserEmailTokens",
            {
                "key": {
                    "type": Sequelize.STRING,
                    "field": "key",
                    "primaryKey": true
                },
                "type": {
                    "type": Sequelize.STRING,
                    "field": "type",
                    "validate": {
                        "notEmpty": true
                    }
                },
                "sub": {
                    "type": Sequelize.STRING,
                    "field": "sub"
                },
                "redirect_uri": {
                    "type": Sequelize.STRING,
                    "field": "redirect_uri",
                    "allowNull": true
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "field": "created_at",
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "field": "updated_at",
                    "allowNull": false
                },
                "user_id": {
                    "type": Sequelize.INTEGER,
                    "field": "user_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                },
                "oauth2_client_id": {
                    "type": Sequelize.INTEGER,
                    "field": "oauth2_client_id",
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "OAuth2Clients",
                        "key": "id"
                    },
                    "allowNull": true
                }
            },
            {}
        ]
    },
    {
        fn: "createTable",
        params: [
            "Sessions",
            {
            "sid": {
                "type": Sequelize.STRING,
                "primaryKey": true,
                "field": "id",
                "allowNull": false
            },
            "userId": {
                    "type": Sequelize.STRING,
                    "field": "userId"
                },
                "expires": {
                    "type": Sequelize.DATE,
                },
                "data": {
                    "type": Sequelize.STRING(10000)
                }
            }
        ]
    },
    {
        fn: "addIndex",
        params: [
            "SocialLogins",
            ["user_id", "name"],
            {
                "indicesType": "UNIQUE"
            }
        ]
    },
    {
        fn: "addIndex",
        params: [
            "OAuth2RefreshTokens",
            ["key"],
            {
                "indicesType": "UNIQUE"
            }
        ]
    },
    {
        fn: "addIndex",
        params: [
            "Sessions",
            ["expires"],
            {
                "indexName": "sessions_expire_idx"
            }
        ]
    },
    {
        fn: "addIndex",
        params: [
            "Sessions",
            ["sid"],
            {
                "indexName": "sessions_sid_idx"
            }
        ]
    }
];

var db = require('../../models');

function initDb(queryInterface, pos) {
    var index = pos;
    return new Promise(function(resolve, reject) {
        function next() {
            if (index < migrationCommands.length)
            {
                let command = migrationCommands[index];
                console.log("[#"+index+"] execute: " + command.fn);
                index++;
                queryInterface[command.fn].apply(queryInterface, command.params).then(next, reject);
            }
            else
                resolve();
        }
        next();
    });
}

module.exports = {
    pos: 0,
    up: function(queryInterface, Sequelize)
    {
        return db.sequelize.query('SELECT count(*) FROM `SequelizeMeta`', { type: db.sequelize.QueryTypes.SELECT}).then(count => {
            console.log('count', count[0]['count(*)']);
            if (count[0]['count(*)'] > 0) {
                return new Promise(function(resolve, reject) {
                    //nothing
                    console.log('Legacy database => nothing to do.');
                    resolve();
                });
            } else {
                console.log('initDb...');
                return initDb(queryInterface, this.pos);
            }
        }).catch((e) => {
            // Table doesn't exists
            console.log('Table doesn\'t exists', e);
            return initDb(queryInterface, this.pos);
        });

    },
    info: info
};
