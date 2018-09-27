'use strict';

var callbackServer = process.env.OAUTH2_CALLBACK || 'http://192.168.99.100:3001';

module.exports = {

    identity_providers: {
        oauth: {
            enabled: true,
            client_id: process.env.OAUTH2_CLIENT_ID,
            client_secret: process.env.OAUTH2_CLIENT_SECRET,
            callback_url: callbackServer + '/auth/oauth/callback'
        }
    },

    db: {
        // The database type, 'mysql', 'sqlite', etc.
        type: 'sqlite',

        // Database filename for SQLite.
        filename: 'data/identity.sqlite',

        // If true, SQL statements are logged to the console.
        debug: true
    },

    // Session cookie is signed with this secret to prevent tampering
    session_secret: 'thisIsNotABigSecretThisIsJustDemoClient'

};
