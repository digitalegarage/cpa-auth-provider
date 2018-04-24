'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        if (process.env.DB_TYPE === 'sqlite') {
            return resolve();
        }
        return queryInterface.getForeignKeyReferencesForTable('LocalLogins').then(function (detail) {
            var constraint = getRowForColumn('login', details);
            return queryInterface.removeConstraint('LocalLogins', constraint.constraintName);

        }).then(function () {
            return queryInterface.addConstraint(
                'LocalLogins',
                ['login'],
                {
                    type: 'foreign key',
                    name: 'LocalLogins_login_key',
                    references: {table: 'Users', fields: [sequelize.fn('lower', sequelize.col('login'))]}
                }
            );
        });
    },

    down: function (queryInterface, Sequelize) {
        return resolve();
    }

}
