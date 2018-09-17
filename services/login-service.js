var config = require('../config');
var db = require('../models');
var passwordHelper = require('../lib/password-helper');
var permissionName = require('../lib/permission-name');
var codeHelper = require('../lib/code-helper');
var emailHelper = require('../lib/email-helper');
var finder = require('../lib/finder');
var xssFilters = require('xss-filters');
var userHelper = require('../lib/user-helper');
var errors = require('./errors');


module.exports = {
    checkSignupData: checkSignupData,
    signup: signup
};

const ERRORS = {
    EMAIL_TAKEN: 'email already exists',
    PASSWORD_WEAK: 'Password is not strong enough',
    MISSING_FIELDS: 'missing required fields',
    UNKNOWN_GENDER: 'UNKNOWN_GENDER',
    MALFORMED_DATE_OF_BIRTH: 'MALFORMED_DATE_OF_BIRTH',
    INVALID_LAST_NAME: 'INVALID_LAST_NAME',
    INVALID_FIRST_NAME: 'INVALID_FIRST_NAME',
    RECAPTCHA_ERROR: 'RECAPTCHA_ERROR',

};

function checkSignupData(req) {
    return new Promise((resolve, reject) => {
        if (req.recaptcha.error) {
            errors.throwValidationError(ERRORS.RECAPTCHA_ERROR);
        }

        var missingFields = [];
        if (!req.body.email) {
            missingFields.push('email');
        }
        if (!req.body.password) {
            missingFields.push('password');
        }
        if (missingFields.length > 0) {
            errors.throwValidationError(ERRORS.MISSING_FIELDS, {missingFields: missingFields});
        }

        var email = req.body.email;
        var password = req.body.password;

        if (!passwordHelper.isStrong(email, password)) {
            errors.throwValidationError(ERRORS.PASSWORD_WEAK);
        }

        // userAttributes is a merge of requiredAttributes and optionnalAttributes
        var userAttributes = {display_name: email};
        var requiredAttributes = getRequiredAttributes(req);
        for (var a in requiredAttributes) {
            userAttributes[a] = requiredAttributes[a];
        }
        var optionnalAttributes = getOptionnalAttributes(req);
        for (var oa in optionnalAttributes) {
            userAttributes[oa] = optionnalAttributes[oa];
        }

        validateFields(requiredAttributes);
        validateFiledsValues(optionnalAttributes);

        return finder.findUserByLocalAccountEmail(email)
            .then(function (localLogin) {
                if (localLogin) {
                    errors.throwValidationError(ERRORS.EMAIL_TAKEN);
                }
                return finder.findUserBySocialAccountEmail(email);
            })
            .then(function (socialLogin) {
                if (socialLogin) {
                    // User exist because it has been created by a social login
                    // Since Local login doesn't exist, that mean that the account is not validated
                    // So it's impossible to signup with that email
                    errors.throwValidationError(ERRORS.EMAIL_TAKEN);
                }
                resolve(userAttributes);
            })
            .catch(function (err) {
                reject(err);
            });
    });
}

function signup(userAttributes, email, password) {

    //use XSS filters to prevent users storing malicious data/code that could be interpreted then
    for(var k in userAttributes){
        userAttributes[k] = xssFilters.inHTMLData(userAttributes[k]);
    }

    var localLogin;
    var user;
    return new Promise((resolve, reject) => {
        db.Permission.findOne({where: {label: permissionName.USER_PERMISSION}})
            .then(
                function (permission) {
                    if (permission) {
                        userAttributes.permission_id = permission.id;
                    }
                    return db.sequelize.transaction(function (transaction) {
                        // Code that have to run under a transaction:
                        return db.User.create(userAttributes, {transaction: transaction}).then(
                            function (u) {
                                user = u;
                                return db.LocalLogin.create({
                                    user_id: u.id,
                                    login: email
                                }, {transaction: transaction});
                            }
                        ).then(
                            function (ll) {
                                localLogin = ll;
                                return localLogin.setPassword(password, transaction);
                            }
                        ).then(
                            function () {
                                return codeHelper.getOrGenereateEmailVerificationCode(user, transaction);
                            }
                        ).catch(
                            function (err) {
                                reject(err);
                            }
                        );
                    }).then(
                        function (code) {
                            // Don't need to be part of the transaction
                            localLogin.logLogin(user);
                            emailHelper.send(
                                config.mail.from,
                                localLogin.login,
                                "validation-email",
                                {log: false},
                                {
                                    confirmLink: config.mail.host + '/email_verify?email=' + encodeURIComponent(localLogin.login) + '&code=' + encodeURIComponent(code),
                                    host: config.mail.host,
                                    mail: localLogin.login,
                                    code: code
                                },
                                user.language || config.mail.local
                            );
                            resolve(user);
                        });
                });
    });

}


//////
// Validation

function getRequiredAttributes(req) {
    var requiredAttributes = {};
    config.userProfiles.requiredFields.forEach(
        function (element) {
            if (req.body[element]) {
                requiredAttributes[element] = req.body[element];
            }
        }
    );
    return requiredAttributes;
}

function getOptionnalAttributes(req) {
    var optionnalAttributes = {};
    for (var element in userHelper.getRequiredFields()) {
        if (req.body[element] && !config.userProfiles.requiredFields.includes(element)) {
            optionnalAttributes[element] = req.body[element];
        }
    }
    return optionnalAttributes;
}


function validateFields(attributes) {
    var missingFields = [];
    config.userProfiles.requiredFields.forEach(
        function (element) {
            if (!attributes.hasOwnProperty(element) || !attributes[element]) {
                missingFields.push(element);
            }
        }
    );
    if (missingFields.length > 0) {
        errors.throwValidationError(ERRORS.MISSING_FIELDS, {missingFields: missingFields});
    }

    validateFiledsValues(attributes);
}

var NAME_REGEX = /^[a-zA-Z\u00C0-\u017F -]*$/;

function validateFiledsValues(attributes) {
    if (attributes.hasOwnProperty('gender')) {
        if (typeof(attributes.gender) !== 'string' || !attributes.gender.match(/(male|female|other)/)) {
            errors.throwValidationError(ERRORS.UNKNOWN_GENDER);
        }
    }

    if (attributes.hasOwnProperty('date_of_birth')) {
        if (typeof(attributes.date_of_birth) === 'string' && !attributes.date_of_birth.match(/\d*/)) {
            errors.throwValidationError(ERRORS.MALFORMED_DATE_OF_BIRTH);
        } else if (typeof(attributes.date_of_birth) !== 'string' && typeof(attributes.date_of_birth) !== 'number') {
            errors.throwValidationError(ERRORS.MALFORMED_DATE_OF_BIRTH);
        }
    }

    if (attributes.hasOwnProperty('lastname')) {
        if (typeof(attributes.lastname) !== 'string' || !attributes.lastname.match(NAME_REGEX)) {
            errors.throwValidationError(ERRORS.INVALID_LAST_NAME);
        }
    }
    if (attributes.hasOwnProperty('firstname')) {
        if (typeof(attributes.firstname) !== 'string' || !attributes.firstname.match(NAME_REGEX)) {
            errors.throwValidationError(ERRORS.INVALID_FIRST_NAME);
        }
    }
}
