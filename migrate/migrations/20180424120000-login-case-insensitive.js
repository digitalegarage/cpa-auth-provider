'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        if (process.env.DB_TYPE === 'sqlite') {
            return resolve();
        }
        return queryInterface.removeConstraint('LocalLogins', 'LocalLogins_login_key')
            .then(function () {
                console.log("contraint dropped!")
                return queryInterface.addConstraint(
                    'LocalLogins',
                    ['login'],
                    {
                        type: 'foreign key',
                        name: 'LocalLogins_login_key',
                        references: {table: 'Users', fields: [sequelize.fn('lower', sequelize.col('login'))]}
                    }
                );
            }).catch(function (e) {
                console.log('Something went wrong:', e);
            });
    },

    down: function (queryInterface, Sequelize) {
        return resolve();
    }

};

