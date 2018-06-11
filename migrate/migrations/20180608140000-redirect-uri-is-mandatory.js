'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {

        return queryInterface.changeColumn(
            'OAuth2Clients',
            'redirect_uri',
            {
                type: Sequelize.STRING,
                allowNull: false}
        );
    },

    down: function (queryInterface, Sequelize) {
        return queryInterface.changeColumn(
            'OAuth2Clients',
            'redirect_uri',
            {
                type: Sequelize.STRING,
                allowNull: true}
        );;
    }

};




