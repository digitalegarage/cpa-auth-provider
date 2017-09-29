'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            queryInterface.removeColumn('Users', 'provider_uid').then(
                function () {
                    return queryInterface.createTable(
                        'OAuthProviders',
                        {
                            id: {
                                type: Sequelize.INTEGER,
                                primaryKey: true,
                                autoIncrement: true
                            },
                            created_at: {
                                type: Sequelize.DATE
                            },
                            updated_at: {
                                type: Sequelize.DATE
                            },
                            name: Sequelize.STRING,
                            uid: Sequelize.STRING,
                            //foreign key usage
                            user_id: {
                                type: Sequelize.INTEGER,
                                references: {
                                    model: 'Users',
                                    key: 'id'
                                }
                            }
                        });

                }
            ).then(resolve).catch(reject);
        });
    },

    down: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            queryInterface.removeColumn('UserProfiles', 'date_of_birth').then(
                function () {
                    return queryInterface.dropTable('OAuthProviders');
                }
            ).then(resolve).catch(reject);
        });
    }
};
