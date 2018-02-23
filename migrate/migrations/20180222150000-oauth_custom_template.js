'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        // Add new columns to table Users
        return queryInterface.addColumn(
            "OAuth2Client",
            "use_template",
            {
                type: Sequelize.STRING,
                allowNull: true
            }
        );
    },

    down: function (queryInterface, Sequelize) {
        // Add new columns to table Users
        return queryInterface.removeColumn(
            "OAuth2Client",
            "use_template",
            {
                type: Sequelize.STRING,
                allowNull: true
            }
        );
    }
}
