"use strict";

module.exports = {
    baseUrl: 'http://localhost',

    broadcaster: {
        title: ''
    },

    recaptcha: {
        enabled: true,
        site_key: '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI',
        secret_key: '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
    },


    jwtSecret: 'bigsecret',
    jwt: {
        audience: 'cpa',
        issuer: 'cpa'
    },

    i18n: {
        cookie_name: 'language',
        cookie_duration: 365 * 24 * 60 * 60 * 1000,
        default_locale: 'en'
    },

    identity_providers: {
        facebook: {
            enabled: true,
            client_id: 'abc',
            client_secret: '123'
        },
        github: {
            enabled: false
        },
        ebu: {
            enabled: false
        },
        google: {
            enabled: true,
            client_id: 'abc',
            client_secret: '123'
        },
        twitter: {
            enabled: false
        },
        local: {
            enabled: true
        }
    },

    trackingCookie: {
        enabled: true
    },

    mail: {
        sending: {transport: 'test'},
        from: 'no-reply@rts.ch',
        locale: 'ch_fr',
        host: 'http://localhost:3000'
    },

    password: {
        // in sec
        recovery_code_validity_duration: 1800,
        // a new recovery code will be generated only if the current one has less that TTL
        keep_recovery_code_until: 900
    },

    auto_idp_redirect: 'local',

    db: {
        // The database type, 'mysql', 'sqlite', etc.
        type: 'sqlite',

        // Database filename for SQLite.
        // filename: 'data/test.sqlite',

        // If true, SQL statements are logged to the console.
        debug: false
    },

    // Session cookie is signed with this secret to prevent tampering
    session_secret: 'LKASDMjnr234n90lasndfsadf',

    // Name of the session cookie. Must be something different than 'connect.sid'
    sid_cookie_name: 'identity.provider.sid',

    enableCORS: true,

    displayUsersInfos: true,

    displayMenuBar: false,

    // Cross-origin resource sharing
    cors: {
        enabled: true,
        allowed_domains: [
            'http://localhost.rts.ch:8080'
        ]
    },

    // URL path prefix, e.g., '/myapp'
    urlPrefix: '/ap',

    // The end-user verification URI on the authorization server. The URI should
    // be short and easy to remember as end-users will be asked to manually type
    // it into their user-agent.
    verification_uri: 'http://example.com/verify',

    domains: [
        {
            name: 'bbc1-cpa.ebu.io',
            display_name: 'BBC1',
            access_token: 'b4949eba147f4cf88985b43c039cd05b'
        },
        {
            name: 'bbc2-cpa.ebu.io',
            display_name: 'BBC2',
            access_token: 'b3dd734356524ef9b9ab3d03f1b1558e'
        }
    ],

    permissions: [
        {
            id: 1,
            label: "admin"
        },
        {
            id: 2,
            label: "other"
        }
    ],

    // This option controls how the authorization server responds to requests to
    // associate an existing client with a new domain:
    // - false: The user must authenticate and confirm access to the new domain
    // - true: The user is automatically granted access without confirmation
    auto_provision_tokens: false,

    // The length of time that user (pairing) codes are valid, in seconds.
    pairing_code_lifetime: 60 * 60, // 1 hour

    // The length of time that a access tokens are valid, in seconds.
    access_token_lifetime: 30 * 24 * 60 * 60, // 30 days

    // The length of time that an authorization code is valid, in seconds.
    authorization_code_lifetime: 10 * 60, // 10 minutes

    // The maximum rate at which clients should poll to obtain an access token,
    // in seconds.
    max_poll_interval: 5,

    server_clients: [],

    oauth2: {
        refresh_tokens_enabled: true
    }
};
