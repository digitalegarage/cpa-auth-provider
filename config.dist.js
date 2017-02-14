"use strict";

module.exports = {
  identity_providers: {
    // Details : http://passportjs.org/guide/facebook/
    facebook: {
      enabled: false,
      client_id: '',
      client_secret: '',
      callback_url: ''
    },
    github: {
      enabled: true,
      client_id: '',
      client_secret: '',
      callback_url: ''
    },
    ebu: {
      enabled: false
    },
    local: {
      enabled: false
    }
  },

  mail: {
    sending: {
      // transport: 'sendmail'
      // transport: 'stream'
      transport: 'gmail',
      username: 'ebuidp@gmail.com',
      password: 'HalloEBU',
    },
    from:'no-reply@rts.ch',
    locale:'ch_fr',
    host:'http://localhost:3000'
  },

  password: {
    // in sec
    recovery_code_validity_duration: 1800,
    // a new recovery code will be generated only if the current one has less that TTL
    keep_recovery_code_until: 900
  },

  trackingCookie: {
    enabled: false,
    secret: 'secret phrase',
    // name: 'TrackingId',
    duration: 10 * 365 * 24 * 60 * 60 * 1000 // 10 years
  },
  recaptcha: {
    site_key: '6Lf8JhIUAAAAAOpDYjfIZnlxmjhPQblCiwwfSPHc',
    secret_key: '6Lf8JhIUAAAAADblMNVnlvE0Sbg8_P_NwM87IncZ'
  },

  // When accessing the home page, if defined, users are automatically
  // redirected to the specified identity_providers (ie: 'github')
  auto_idp_redirect: '',

  db: {
    host: '',
    port: 3306,
    user: '',
    password: '',

    // The database type, 'mysql', 'sqlite', etc.
    type: '',
    database: '',

    // Database filename for SQLite.
    filename: '',

    // If true, SQL statements are logged to the console.
    debug: true
  },

  // Session cookie is signed with this secret to prevent tampering
  session_secret: 'LKASDMjnr234n90lasndfsadf',

  // Name of the session cookie. Must be something different than 'connect.sid'
  sid_cookie_name: 'identity.provider.sid',

  // Cross-origin resource sharing
  cors: {
    enabled: true,
    allowed_domains: [
      "http://cpa-client.ebu.io"
    ]
  },

  // URL path prefix, e.g., '/myapp'
  urlPrefix: '',

  // The end-user verification URI on the authorization server. The URI should
  // be short and easy to remember as end-users will be asked to manually type
  // it into their user-agent.
  verification_uri: 'http://vagrant.ebu.io:3000/',

  domains: [
    {
      name:         'bbc1-cpa.ebu.io',
      display_name: 'BBC1',
      access_token: 'b4949eba147f4cf88985b43c039cd05b'
    },
    {
      name:         'bbc2-cpa.ebu.io',
      display_name: 'BBC2',
      access_token: 'b3dd734356524ef9b9ab3d03f1b1558e'
    }
  ],

  roles: [
    {
      id:       1,
      label:    "admin"
    },
    {
      id:       2,
      label:    "other"
    }
  ],

  // This option controls how the authorization server responds to requests to
  // associate an existing client with a new domain:
  // - false: The user must authenticate and confirm access to the new domain
  // - true: The user is automatically granted access without confirmation
  auto_provision_tokens: false,

  server_clients : [{
    name: '',
    software_id: '',
    software_version: '',
    ip: '127.0.0.1',
    secret: '',
    registration_type: 'static',
    redirect_uri: ''
  }],

  // The length of time that user (pairing) codes are valid, in seconds.
  pairing_code_lifetime: 60 * 60, // 1 hour

  // The length of time that a access tokens are valid, in seconds.
  access_token_lifetime: 24 * 60 * 60, // 1 day

  // The length of time that an authorization code is valid, in seconds.
  authorization_code_lifetime: 10 * 60, // 10 minutes

  // The maximum rate at which clients should poll to obtain an access token,
  // in seconds.
  max_poll_interval: 5,
};
