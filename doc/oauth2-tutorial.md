# OAuth 2 Client
Single sign on services allow your users to log into multiple
services and apps with a single account.
As a prerequisite for this tutorial you need to be running
the identity-provider. (See previous tutorial.)

## Why OAuth 2.0?
OAuth 2.0 is an internet standard protocol and allows easy
adoption by using existing libraries. It also enables fast
integration of other services that use the same protocol.

## How does it work?
A user is represented by access tokens.

In order to get an access token for an user, the service or
app needs to have the user login to the identity provider.

The identity provider will only forward any form of user
identity if the service has a valid client id and client
secret.

## Task 1: Create client_id and client_secret
* log into identity provider
* create new app
* generate client_id and client_secret for OAuth 2.0

## Task 2: Setup passport strategy
For node there's a simple module available for passport
to use OAuth 2.0.

In a first step you need to configure the passport-oauth2
strategy. Insert the client id and secret as generated in task 1.
You should replace the addresses with the correct ones - you can
use `http://localhost:3000` for local testing.

```javascript
// how the identity provider can be reached from the users browser
var server = 'http://your.ip.address:3000';
// how the identity provider can be reached from this server - could be a docker instance name
var serverInternal = 'http://localhost:3000';
// how this service is reachable from the users browser
var callbackServer = 'http://your.ip.address:3001';

// oauth 2 configuration for the passport strategy
var oauth2_config = {
	tokenURL: serverInternal + '/oauth2/token',
	authorizationURL: server + '/oauth2/dialog/authorize',
	// insert client id and secret as created in task 1
	clientID: 'client-id-as-generated',
	clientSecret: 'client-secret-as-generated',
	callbackURL: callbackServer + '/auth_code/callback'
};
```

It's also required to make an adjustment to the OAuth 2.0 strategy
to get proper user profiles.

```javascript
var passport = require('passport');
var OAuth2Strategy = require('passport-oauth2');
var request = require('request');

OAuth2Strategy.prototype.userProfile = function (accessToken, done) {
	var options = {
		url: serverInternal + '/oauth2/user_info',
		headers: {
			'User-Agent': 'request',
			'Authorization': 'Bearer ' + accessToken,
		}
	};

	request(options, callback);
	
	function callback(error, response, body) {
		if (error || response.statusCode !== 200) {
			return done(error);
		}
		var info = JSON.parse(body);
		return done(null, info.user);
	}
};
```

And then you need to tell passport to use that particular strategy.
The strategy will take care of using the authorization code to
get access and refresh tokens.

```javascript
passport.use(
	'oauth2',
	new OAuth2Strategy(
		oauth2_config,
	    function (req, accessToken, refreshToken, params, profile, done) {
	        // do something with the profile
		    done(null, profile);
	    }
    )
);
```

## Task 3: setup endpoints
With express it is straightforward to setup the login redirection,
and the associated callback.

```javascript
	// start the login process using passport-oauth2 strategy
	router.get(
		'/auth_code/oauth',
		passport.authenticate('oauth2')
	);

	// callback when the authorization server (idp) provided an authorization code
	router.get(
		'/auth_code/callback',
		passport.authenticate('oauth2', {failureRedirect: '/auth_code/error'}),
		function (req, res) {
			res.redirect('/');
		}
	);
```

You will still need to put a link on a page somewhere that sends
the user to `/auth_code/oauth`.

```html
<!DOCTYPE html>
<html>
<head></head>
<body>
    <a href="/auth_code/oauth">Authorization Code Flow</a>
</body>
</html>
```

## The complete Sample
There's also a sample implementation available as part of
the code. See /oauth2-client/routes/auth-code-flow.js and
/oauth2-client/views/auth_code.ejs

The sample code at /oauth2-client also contains implementations
of implicit grant flow and resource password owner flow.

