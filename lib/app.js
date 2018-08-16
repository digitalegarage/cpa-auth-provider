"use strict";

// Module dependencies
var express = require('express');

// Express middleware
var favicon = require('serve-favicon');
var bodyParser = require('body-parser');
var methodOverride = require('method-override');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var morgan = require('morgan');
var serveStatic = require('serve-static');
var errorHandler = require('errorhandler');
var flash = require('connect-flash');
var expressValidator = require('express-validator');
var Raven = require('raven');
var accesslog = require('access-log');
var swaggerUi = require('swagger-ui-express');


var passport = require('passport');
var path = require('path');
var fs = require('fs');

var config = require('../config');
var db = require('../models');
var appHelper = require('./app-helper');
var permissionHelper = require('./permission-helper');
var permissionName = require('./permission-name');
var i18n = require('i18n');
var recaptcha = require('express-recaptcha');

// Server
var app = express();

// Routes
var urlPrefix = config.urlPrefix || '';

if (config.trust_proxy) {
    // enable trusting of X-Forwarded-For headers
    app.enable('trust proxy');
}


// Google reCAPTCHA
if (config.limiter.type === 'recaptcha' || config.limiter.type === 'recaptcha-optional') {
    var captcha_options = {
        render: 'explicit',
        hl: i18n.getLocale()
    };
    recaptcha.init(config.limiter.parameters.recaptcha.site_key, config.limiter.parameters.recaptcha.secret_key, captcha_options);
}

// Error handling
if (config.sentry && config.sentry.dsn) {
    Raven.config(config.sentry.dsn).install();
    // The request handler must be the first middleware on the app
    app.use(Raven.requestHandler());
} else {
    if (app.get('env') !== 'test') {
        app.use(errorHandler());

        const monitor = require('./monitor');
        monitor.start();
    }
}

//Swagger
var swaggerJSDoc = require('swagger-jsdoc');

var options = {
    swaggerDefinition: {
        info: {
            title: 'Identity provider',
            version: '2.0.0',
        },
    },
    apis: ['./routes/api/v2/user/profile-resource.js', './routes/api/v2/public/user-resource.js'], // Path to the API docs
};
const swaggerSpec = swaggerJSDoc(options);

app.use(urlPrefix + '/api/v2/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get(urlPrefix + '/api/v2/api-docs.json', function (req, res) {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
});

//CPA middleware: store user in request object if it can be found (i.e.: authenticated) via a cpa token
var cpaMiddleWare = function (req, res, next) {
    var cpaToken = req.header('Authorization');
    if (cpaToken) {
        cpaToken = cpaToken.replace('Bearer ', '');
        db.AccessToken.findOne({where: {token: cpaToken}, include: [db.User]})
            .then(function (accessToken) {
                if (accessToken) {
                    if (accessToken.User) {
                        req.user = accessToken.User;
                    }
                }
                next();
            });
    } else {
        next();
    }
};
app.use(cpaMiddleWare);

app.set('port', process.env.PORT || 3000);

// Allow EJS access to config and permission
app.locals.config = config;
app.locals.permissionName = permissionName;

//Broadcaster specific layout
app.locals.broadcaster = {
    name: 'default'
};

if (config.broadcaster && config.broadcaster.layout) {
    app.locals.broadcaster.name = config.broadcaster.layout;
}

// Templates
app.set('views', path.join(__dirname, '..', 'views'));
app.set('view engine', 'ejs');

var faviconPath = path.join(__dirname, '..', 'public/', 'favicon', 'favicon.ico');
if (config.broadcaster && config.broadcaster.layout) {
    var broadcasterFaviconPath = path.join(__dirname, '..', 'public', 'favicon', config.broadcaster.layout, 'favicon.ico');
    if (fs.existsSync(broadcasterFaviconPath)) {
        faviconPath = broadcasterFaviconPath;
    }
}
app.use(favicon(faviconPath));

// redirect jquery
app.use(urlPrefix + '/js', express.static(__dirname + '/../node_modules/jquery/dist'));
app.use(urlPrefix + '/jquery-form', express.static(__dirname + '/../node_modules/jquery-form/dist'));
app.use(urlPrefix + '/cookie', express.static(__dirname + '/../node_modules/js-cookie'));
// redirect bootstrap
app.use(urlPrefix + '/bootstrap', express.static(__dirname + '/../node_modules/bootstrap'));
// redirect bootstrap datepicker
app.use(urlPrefix + '/bootstrap-datepicker', express.static(__dirname + '/../node_modules/bootstrap-datepicker'));
// redirect owasp password strength test lib
app.use(urlPrefix + '/owasp', express.static(__dirname + '/../node_modules/owasp-password-strength-test'));
// redirect moment
app.use(urlPrefix + '/moment', express.static(__dirname + '/../node_modules/moment'));
// redirect public files
app.use(urlPrefix + '/assets', express.static(__dirname + '/../public'));

// Set up express web server logging via winston, but don't enable logging
// when running unit tests.

var logger = require('./logger');

if (process.env.NODE_ENV !== "test") {
    var stream = {
        write: function (message, encoding) {
            return logger.info(message.trimRight());
        }
    };

    app.use(morgan('dev', {stream: stream}));
}

app.use(permissionHelper.middleware());

//check permissions
permissionHelper.use(function (req, access) {
    if (typeof req.user.Permission !== "undefined" && req.user.Permission !== null) {
        if (req.user.Permission.label === access) {
            return true;
        }
    }
});

i18n.configure({
    locales: ['en', 'de', 'fr'],
    directory: __dirname + '/../locales',
    cookie: config.i18n.cookie_name,
    defaultLocale: config.i18n.default_locale,
    autoReload: true
});

app.use(bodyParser.json());
// this line must be immediately after any of the bodyParser middlewares!
app.use(expressValidator({
    customValidators: {
        isValidDate: isValidDate
    }
}));

function isValidDate(dateString) {
    // First check for the pattern
    if (!/^\d{4}-\d{1,2}-\d{1,2}$/.test(dateString))
        return false;

    // Parse the date parts to integers
    var parts = dateString.split("-");
    var year = parseInt(parts[0], 10);
    var month = parseInt(parts[1], 10);
    var day = parseInt(parts[2], 10);

    // Check the ranges of month and year
    if (year < 1000 || year > 3000 || month == 0 || month > 12)
        return false;

    var monthLength = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

    // Adjust for leap years
    if (year % 400 == 0 || (year % 100 != 0 && year % 4 == 0))
        monthLength[1] = 29;

    // Check the range of the day
    return day > 0 && day <= monthLength[month - 1];
}

app.use(bodyParser.urlencoded({extended: true}));
app.use(methodOverride());

// Passport and i18n
app.use(cookieParser());
// i18n configuration
app.use(i18n.init);
app.use(session(appHelper.sessionOptions(express)));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash()); // use connect-flash or flash messages stored in session

appHelper.initPassportSerialization(passport);
appHelper.headerHelper(app, logger);

// Templates
// Add user to templates scope
app.use(appHelper.templateVariables);

app.use(require('./response-helper')(logger));


app.use(require('./url-prefix')(urlPrefix));

var router = express.Router();


// Allow to switch language by adding ?defaultLanguage=en/fr/de in any url
// And manage access log
var format = config.access_log_format;
app.all('*', function (req, res, next) {

    if (format) {
        accesslog(req, res, format, function (s) {
            logger.debug(s);
        });
    }

    if (req.query.defaultLanguage) {
        i18n.setLocale(req, req.query.defaultLanguage);
        res.cookie(config.i18n.cookie_name, req.query.defaultLanguage, {
            maxAge: config.i18n.cookie_duration,
            httpOnly: true
        });
        res.locals.language = req.query.defaultLanguage;
    }
    next();
});

require('../routes/access-token')(router);
require('../routes/association')(router);
require('../routes/authorization')(router, config);
require('../routes/index')(router);
require('../routes/registration')(router);
require('../routes/status')(router);
require('../routes/verification')(router);
require('../routes/quality-check')(router);
require('../routes/admin/index')(router);
require('../routes/auth/index')(router);
require('../routes/auth/oauth-local')(router);
require('../routes/user/index')(router);
require('../routes/user/client')(router);
require('../routes/user/profile')(router);
require('../routes/user/i18n')(router);
require('../routes/device')(router);
require('../routes/oauth2/index')(router);
require('../routes/oauth2/profile')(router);
require('../routes/api/user-profile')(router);
require('../routes/email/verify-email')(router);
require('../routes/user/password')(router);
require('../routes/oauth2/client-control')(router);
require('../routes/user/verify')(router);
require('../routes/oauth2/user-delete')(router);
require('../routes/email/change-email')(router);
require('../routes/api/v2/user/profile-resource')(router);
require('../routes/api/v2/user/user-resource')(router);

router.use(serveStatic(path.join(__dirname, '..', 'public')));

app.use(urlPrefix, router);


db.sequelize
    .authenticate()
    .then(
        function () {
            if (process.env.NODE_ENV !== 'test') {
                logger.info('Database connection has been established successfully.');
                require('./user-deletion').start();
            }
        },
        function (err) {
            logger.error('Unable to connect to the database.', err);
        }
    );

// Error handling with sentry (have to be done at the end of that file for some reason...)
if (config.sentry && config.sentry.dsn) {
    // The error handler must be before any other error middleware
    app.use(Raven.errorHandler());
    app.use(function (err, req, res, next) {
        res.statusCode = 500;
        if (res.sentry) {
            res.end('Unexpected error :( => it will be reported in our system with id ' + res.sentry + '\n');
        } else {
            Raven.captureException(new Error("system is returing 500 error to request [" + req.method + "] " + req.url));
            res.end('Unexpected error :( => it will be reported in our system\n');
        }
    });
}


module.exports = app;
