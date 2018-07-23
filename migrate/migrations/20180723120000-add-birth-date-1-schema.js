'use strict';

module.exports = {
    up: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            queryInterface.addColumn(
                "Users",
                "birth_date",
                {
                    type: Sequelize.DATEONLY,
                    allowNull: true
                }
            ).then(function () {
                queryInterface.addColumn(
                    "SocialLogins",
                    "birth_date",
                    {
                        type: Sequelize.DATEONLY,
                        allowNull: true
                    }
                )
            }).then(function () {
                if (process.env.DB_TYPE === "postgres") {
                    var offSet = new Date().getTimezoneOffset();
                    return queryInterface.sequelize.query("UPDATE public.\"Users\" SET birth_date = TO_TIMESTAMP(date_of_birth / 1000 -1*(" + offSet + "*60))::date").then(function () {
                        return queryInterface.sequelize.query("UPDATE public.\"SocialLogins\" SET birth_date = TO_TIMESTAMP(date_of_birth::bigint / 1000 -1*(" + offSet + "*60))::date");
                    });
                } else {
                    // Only RTS using postgres use profile with birth date
                    return new Promise(function (resolve, reject) {
                    });
                }
            }).then(resolve).catch(reject);
        });
    },

    down: function (queryInterface, Sequelize) {
        return new Promise(function (resolve, reject) {
            return queryInterface.removeColumn('Users', 'birth_date').then(function () {
                return queryInterface.removeColumn('SocialLogins', 'birth_date')
            }).then(resolve).catch(reject);
        });
    }
}
