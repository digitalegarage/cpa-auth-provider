'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        /*
          Add altering commands here.
          Return a promise to correctly handle asynchronicity.

          Example:
          return queryInterface.createTable('users', { id: Sequelize.INTEGER });
        */
        return queryInterface.createTable(
            "AccessTokens",
            {
                "id": {
                    "type": Sequelize.INTEGER,
                    "autoIncrement": true,
                    "primaryKey": true
                },
                "token": {
                    "type": Sequelize.STRING(255),
                    "validate": {
                        "notEmpty": true
                    }
                },
                "created_at": {
                    "type": Sequelize.DATE,
                    "allowNull": false
                },
                "updated_at": {
                    "type": Sequelize.DATE,
                    "allowNull": false
                },
                "client_id": {
                    "type": Sequelize.INTEGER,
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
                    "onUpdate": "CASCADE",
                    "onDelete": "SET NULL",
                    "references": {
                        "model": "Users",
                        "key": "id"
                    },
                    "allowNull": true
                }
            }
        );
    },

    down: function (queryInterface, Sequelize) {
        /*
          Add reverting commands here.
          Return a promise to correctly handle asynchronicity.

          Example:
          return queryInterface.dropTable('users');
        */
        return queryInterface.dropTable(
            'AccessTokens'
        );
    }
};
