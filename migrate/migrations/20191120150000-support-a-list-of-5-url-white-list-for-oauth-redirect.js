/* jslint node:true, esversion:6 */
'use strict';

module.exports = {
    up: function(queryInterface, Sequelize) {

        return queryInterface.addColumn(
            'Client',
            'redirect_uri_2',
            Sequelize.STRING
        ).then(()=>{
            return queryInterface.addColumn(
                'Client',
                'redirect_uri_3',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'Client',
                'redirect_uri_4',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'Client',
                'redirect_uri_5',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'OAuth2Client',
                'redirect_uri_2',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'OAuth2Client',
                'redirect_uri_3',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'OAuth2Client',
                'redirect_uri_4',
                Sequelize.STRING)
        }).then(()=>{
            return queryInterface.addColumn(
                'OAuth2Client',
                'redirect_uri_5',
                Sequelize.STRING)
        });
    },

    down: function(queryInterface, Sequelize) {

        return queryInterface.removeColumn(
            'Client',
            'redirect_uri_2'
        ).then(()=>{
            return queryInterface.removeColumn(
                'Client',
                'redirect_uri_3')
        }).then(()=>{
            return queryInterface.removeColumn(
                'Client',
                'redirect_uri_4')
        }).then(()=>{
            return queryInterface.removeColumn(
                'Client',
                'redirect_uri_5')
        }).then(()=>{
            return queryInterface.removeColumn(
                'OAuth2Client',
                'redirect_uri_2')
        }).then(()=>{
            return queryInterface.removeColumn(
                'OAuth2Client',
                'redirect_uri_3')
        }).then(()=>{
            return queryInterface.removeColumn(
                'OAuth2Client',
                'redirect_uri_4')
        }).then(()=>{
            return queryInterface.removeColumn(
                'OAuth2Client',
                'redirect_uri_5')
        });
    }
}