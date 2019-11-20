

# Login with mobile view

That login flow was designed for RTS but could apply to any broadcaster aiming to have a single login widow that could be used with mobile via a web view or as a stand alone web page for web login.

## Flow (big picture)

### basic (aka web)

The user enter his credentials (or signup information) in case of success he is redirected to IDP root "/"

### basic (aka web) + redirect

The user enter his credentials (or signup information) in case of success he is redirected tot he url passed as query parameter.
A typical use case would be a user requesting a secured page without session. The user would be redirected to the login page with the secured page as query parameter.
Note that redirect url parameter is checked against a white list configured on IDP.


### redirect + cookie extraction

That flow is not supposed to be used in a pur web mode since it can leak the session cookie to an evil JS. It has been designed for mobile login using a web view and that require to get the session cookie value for later use in a native context. 
Expected flow is the following: 
- mobile native app open a web view on the IDP login page with a redirect in the HTTP request. That redirect url has a custom schema (like: `ios://login`) that could be easily intercepted by mobile framework.
- once the login or signup succeed the web view is redirected to the requested custom url with the session cookie has a query parameter (like : `ios://login?token=<cookie_value>`)
- the native app intercepts the URL and get the cookie value.
- Any call to a secured API from the native app could use a dedicated header (instead of a cookie). That header is `sessionToken`. Sample: `curl "http://secured/" -H 'sessionToken: <cookie_value>'`. Note that a such call would slide the original cookie session as a normal HTTP call with session cookie would.  


#### the hidden redirect:

It's possible to get the cookie value from the `npm-session` lib only after the header are sent to the client, so it's too late to try to set the cookie value as a query parameter in the header `location`. So an additional redirect to `/api/v2/session/cookie` had been added to that flow in order to get the cookie and to finally return it as a query parameter.
So in term of HTTP cal the flow would be the following:
- GET `https://idp/login?redirect=iso%3A%2F%2Flogin` (redirect contains `iso://login` but url encoded)
- POST `https://idp/api/v2/session/login <user> <password>` responds with 302 `location: https://idp/api/v2/session/cookie?redirect=iso%3A%2F%2Flogin`
- GET `https://idp/api/v2/session/cookie?redirect=iso%3A%2F%2Flogin` responds with 302 `location: iso://login?token=<cookie_value>`
- GET `iso://login?token=<cookie_value>`

#### sessionToken header

There is a tweak in `app.js` to support the `sessionToken` header. It's a small piece of code that add the `sessionToken` header value into the cookies header. 
  
```
// support session cookie sent via another header
   app.use(function (req, res, next) {
   
       if (config.session_authorization_header_qualifier &&
           req.headers &&
           req.headers.authorization &&
           req.headers.authorization.indexOf(config.session_authorization_header_qualifier) == 0
       ) {
           var cookies = req.headers.cookie;
           if (!cookies) {
               req.headers.cookie = config.auth_session_cookie.name + '=' + req.headers.authorization.substring(config.session_authorization_header_qualifier.length + 1); // + 1 for space char
           } else {
               var headers = req.headers.cookie.split(';');
               var headersString = '';
               const semiColumn = '; ';
               for (var h = 0; h < headers.length; h++) {
                   if (headers[h].trim().indexOf(config.auth_session_cookie.name) != 0) {
                       headersString += headers[h].trim() + semiColumn;
                   }
               }
               headersString += config.auth_session_cookie.name + '=' + req.headers.authorization.substring(config.session_authorization_header_qualifier.length + 1); // + 1 for space char
   
               req.headers.cookie = headersString;
           }
       }
       next();
   });
```
 