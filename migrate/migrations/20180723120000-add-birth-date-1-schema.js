'use strict';

module.exports = {
    up: function(queryInterface, Sequelize) {
        return new Promise(function(resolve, reject) {
            console.log('addColumn 1');
            queryInterface.addColumn(
                'Users',
                'date_of_birth_ymd',
                {
                    type: Sequelize.DATEONLY,
                    allowNull: true,
                },
            ).then(function() {
                queryInterface.addColumn(
                    'SocialLogins',
                    'date_of_birth_ymd',
                    {
                        type: Sequelize.DATEONLY,
                        allowNull: true,
                    },
                ).then(function() {
                    if (process.env.DB_TYPE === 'postgres') {
                        console.log('postgres');
                        var offSet = new Date().getTimezoneOffset();
                        queryInterface.sequelize.query(
                            'UPDATE public."Users" SET date_of_birth_ymd = TO_TIMESTAMP(date_of_birth / 1000 -1*(' + offSet + '*60))::date',
                        ).then(function() {
                            queryInterface.sequelize.query(
                                'UPDATE public."SocialLogins" SET date_of_birth_ymd = TO_TIMESTAMP(date_of_birth::bigint / 1000 -1*(' + offSet + '*60))::date'
                            ).then(resolve);
                        });
                    } else {
                        // Only RTS using postgres use profile with birth date
                        resolve();
                    }
                }).catch(reject);
            });
        });
    },

    down: function(queryInterface, Sequelize) {
        return new Promise(function(resolve, reject) {
            return queryInterface.removeColumn('Users', 'date_of_birth_ymd').then(function() {
                return queryInterface.removeColumn('SocialLogins', 'date_of_birth_ymd');
            }).then(resolve).catch(reject);
        });
    },
};
