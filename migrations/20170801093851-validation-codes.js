'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        /*
          Add altering commands here.
          Return a promise to correctly handle asynchronicity.

          Example:
          return queryInterface.createTable('users', { id: Sequelize.INTEGER });
        */
        return new Promise(
            function (resolve, reject) {
                queryInterface.createTable(
                    "ValidationCodes",
                    {
                        "id": {
                            "type": Sequelize.INTEGER,
                            "autoIncrement": true,
                            "primaryKey": true
                        },
                        "date": {
                            "type": Sequelize.BIGINT,
                            "validate": {
                                "notEmpty": true
                            }
                        },
                        "value": {
                            "type": Sequelize.STRING(255),
                            "validate": {
                                "notEmpty": true
                            }
                        },
                        "type": {
                            "type": Sequelize.TEXT,
                            "validate": {
                                "notEmpty": true
                            },
                            "defaultValue": "email"
                        },
                        "created_at": {
                            "type": Sequelize.DATE,
                            "allowNull": false
                        },
                        "updated_at": {
                            "type": Sequelize.DATE,
                            "allowNull": false
                        },
                        "user_id": {
                            "type": Sequelize.INTEGER,
                            "onUpdate": "cascade",
                            "onDelete": "set null",
                            "references": {
                                "model": "Users",
                                "key": "id"
                            },
                            "allowNull": true
                        }
                    }
                ).then(
                    resolve
                ).catch(
                    reject
                )
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
        return new Promise(
            function (resolve, reject) {
                queryInterface.dropTable(
                    "ValidationCodes"
                ).then(
                    resolve
                ).catch(
                    reject
                )
            }
        );
    }
};
