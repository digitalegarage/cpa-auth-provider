const config = require('../config');
const db = require('../models');
const passwordHelper = require('../lib/password-helper');
const permissionName = require('../lib/permission-name');
const codeHelper = require('../lib/code-helper');
const emailHelper = require('../lib/email-helper');
const finder = require('../lib/finder');
const xssFilters = require('xss-filters');
const userHelper = require('../lib/user-helper');
const errors = require('./errors');
const isDateFormat = require('is-date-format');
const dateFormat = config.broadcaster && config.broadcaster.date_format ? config.broadcaster.date_format : "dd.mm.yyyy";
const dateAndTime = require('date-and-time')
const Op = db.sequelize.Op;
const afterLoginHelper = require('../lib/afterlogin-helper');


module.exports = {
    checkSignupData: checkSignupData,
    signup: signup,
    login: login
};

const ERRORS = {
    // Signup
    EMAIL_TAKEN: {key: 'EMAIL_TAKEN', message: 'Email already exists', code: 'S1'},
    PASSWORD_WEAK: {key: 'PASSWORD_WEAK', message: 'Password is not strong enough', code: 'S2'},
    MISSING_FIELDS: {key: 'MISSING_FIELDS', message: 'Missing required fields', code: 'S3'},
    UNKNOWN_GENDER: {key: 'UNKNOWN_GENDER', message: 'Unknown gender', code: 'S4'},
    MALFORMED_DATE_OF_BIRTH: {
        key: 'MALFORMED_DATE_OF_BIRTH',
        message: 'Malformed date of birth',
        code: 'S5'
    },
    INVALID_LAST_NAME: {key: 'INVALID_LAST_NAME', message: 'Invalid lastname', code: 'S6'},
    INVALID_FIRST_NAME: {key: 'INVALID_FIRST_NAME', message: 'Invalid firstname', code: 'S7'},
    RECAPTCHA_ERROR: {
        key: 'API_SIGNUP_SOMETHING_WRONG_RECAPTCHA',
        message: 'recaptcha error',
        code: 'S8'
    },

    // Login
    API_INCORRECT_LOGIN_OR_PASS: {
        key: 'API_INCORRECT_LOGIN_OR_PASS',
        message: 'incorrect login or password',
        code: 'L1'
    },

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

function signup(userAttributes, email, password, res) {

    //use XSS filters to prevent users storing malicious data/code that could be interpreted then
    for (var k in userAttributes) {
        userAttributes[k] = xssFilters.inHTMLData(userAttributes[k]);
    }

    if (userAttributes.hasOwnProperty('date_of_birth')) {
        userAttributes.date_of_birth_ymd = dateAndTime.parse(userAttributes.date_of_birth, dateFormat.toUpperCase());
        userAttributes.date_of_birth = userAttributes.date_of_birth_ymd.getTime();
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
                        ).then(
                            function (code) {
                                localLogin.logLogin(user);
                                afterLoginHelper.afterLogin(localLogin.User, email, res);
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
                            }
                        ).catch(
                            function (err) {
                                reject(err);
                            }
                        );
                    });
                });
    });

}

function login(req, res) {
    return new Promise((resolve, reject) => {

        return db.LocalLogin.findOne({
            where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), {[Op.like]: req.body.email.toLowerCase()}),
            include: [db.User]
        }).then(function (localLogin) {
            if (localLogin && req.body.password) {
                localLogin.verifyPassword(req.body.password)
                    .then(function (isMatch) {
                        if (isMatch) {
                            localLogin.logLogin(localLogin.User);
                            afterLoginHelper.afterLogin(localLogin.User, req.body.email || req.query.email, res);
                            resolve(localLogin.User);
                        } else {
                            errors.throwBadCredentialError(ERRORS.API_INCORRECT_LOGIN_OR_PASS);
                        }
                    })
                    .catch(function (err) {
                        reject(err);
                    });
            } else {
                errors.throwBadCredentialError(ERRORS.API_INCORRECT_LOGIN_OR_PASS);
            }
        }).catch(function (err) {
            reject(err);
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
        if (typeof(attributes.date_of_birth) === 'string' && !isDateFormat(attributes.date_of_birth, dateFormat)) {
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
