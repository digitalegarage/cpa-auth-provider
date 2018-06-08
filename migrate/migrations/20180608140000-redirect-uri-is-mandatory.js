'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {

        return queryInterface.changeColumn(
            'OAuth2Clients',
            'redirect_uri',
            {
                allowNull: false,
            }
        );
    },

    down: function (queryInterface, Sequelize) {
        return new Promise((resolve, reject) => {
            return resolve();
        });
    }

};




