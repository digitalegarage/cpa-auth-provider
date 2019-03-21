const config = require('../config');
const db = require('../models');
const passwordHelper = require('../lib/password-helper');
const permissionName = require('../lib/permission-name');
const codeHelper = require('../lib/code-helper');
const emailHelper = require('../lib/email-helper');
const finder = require('../lib/finder');
const xssFilters = require('xss-filters');
const userHelper = require('../lib/user-helper');
const apiErrorHelper = require('../lib/api-error-helper');
const isDateFormat = require('is-date-format');
const dateFormat = config.broadcaster && config.broadcaster.date_format ? config.broadcaster.date_format : "dd.mm.yyyy";
const dateAndTime = require('date-and-time')
const afterLoginHelper = require('../lib/afterlogin-helper');
const uuid = require('uuid');
const parser = require('accept-language-parser');

module.exports = {
    checkSignupData: checkSignupData,
    signup: signup,
    login: login
};

function checkSignupData(req) {
    return new Promise((resolve, reject) => {
        if (req.recaptcha.error) {
            apiErrorHelper.throwError(400, 'RECAPTCHA_ERROR', 'Fail to validate Recaptcha', null, null, req.recaptcha.error);
        }

        var errors = [];
        if (!req.body.email) {
            errors.push(apiErrorHelper.buildErrors('EMAIL_MISSING', 'Email is mandatory', req.__('BACK_SIGNUP_EMAIL_EMPTY_OR_INVALID')));
        }
        if (!req.body.password) {
            errors.push(apiErrorHelper.buildErrors('PASSWORD_MISSING', 'Password is mandatory', req.__('BACK_SIGNUP_PASSWORD_MISSING')));
        }
        if (errors.length > 0) {
            var message =  req.__('BACK_SIGNUP_MISSING_FIELDS');
            for (var i = 0; i < errors.length; i++) {
                message += '<br/>' + '- ' + errors[i].message;
            }
            reject(apiErrorHelper.buildError(400, 'MISSING_FIELDS', 'Some fields are missing see errors arrays', message, errors));
        }

        var email = req.body.email;
        var password = req.body.password;

        if (!passwordHelper.isStrong(email, password)) {
            reject(apiErrorHelper.buildError(400, 'PASSWORD_WEAK', "Password is too weak check which rule applies (could be 'no', 'simple or 'owasp'", req.__('PASSWORD_WEAK')));
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

        return validateFields(requiredAttributes)
        .then(()=> {
            return validateFieldsValues(optionnalAttributes);
        })
        .then(()=> {
            return finder.findUserByLocalAccountEmail(email)
        })
        .then((localLogin) => {
            if (localLogin) {
                reject(apiErrorHelper.buildError(400, 'EMAIL_TAKEN', 'Email '+email+' already taken as local login', req.__('BACK_SIGNUP_EMAIL_TAKEN')));
            }
            return finder.findUserBySocialAccountEmail(email);
        })
        .then(function (socialLogin) {
            if (socialLogin) {
                // User exist because it has been created by a social login
                // Since Local login doesn't exist, that mean that the account is not validated
                // So it's impossible to signup with that email
                reject(apiErrorHelper.buildError(400, 'EMAIL_TAKEN', 'Email '+email+' already taken as social login', req.__('BACK_SIGNUP_EMAIL_TAKEN')));

            } else {
                resolve(userAttributes);
            }
        })
        .catch(function (err) {
            reject(err);
        });
    });
}

function signup(userAttributes, email, password, req, res) {

    //use XSS filters to prevent users storing malicious data/code that could be interpreted then
    for (var k in userAttributes) {
        userAttributes[k] = xssFilters.inHTMLData(userAttributes[k]);
    }

    if (userAttributes.hasOwnProperty('date_of_birth')) {
        userAttributes.date_of_birth_ymd = dateAndTime.parse(userAttributes.date_of_birth, dateFormat.toUpperCase());
        userAttributes.date_of_birth = userAttributes.date_of_birth_ymd.getTime();
    }

    if(!userAttributes.hasOwnProperty('public_uid')){
        userAttributes.public_uid = uuid.v4();
    }

    if (req.headers["accept-language"]){
        let languages = parser.parse(req.headers["accept-language"]);
        if (languages && languages.length){
            userAttributes.language = languages[0].code;
        }
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
                                afterLoginHelper.afterLogin(user, email, res);
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
            where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), req.body.email.toLowerCase()),
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
                            reject(apiErrorHelper.buildError(401, 'INCORRECT_LOGIN_OR_PASSWORD', 'Incorrect login or password', req.__('API_INCORRECT_LOGIN_OR_PASS')));
                        }
                    })
                    .catch(function (err) {
                        reject(err);
                    });
            } else {
                reject(apiErrorHelper.buildError(401, 'INCORRECT_LOGIN_OR_PASSWORD', 'Incorrect login or password', req.__('API_INCORRECT_LOGIN_OR_PASS')));
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
    return new Promise((resolve, reject) => {
        var errors = [];
        config.userProfiles.requiredFields.forEach(
            function(element) {
                if (!attributes.hasOwnProperty(element) || !attributes[element]) {
                    errors.push(apiErrorHelper.buildErrors(element, 'field is missing'));
                }
            }
        );
        if (errors.length > 0) {
            reject(apiErrorHelper.buildError(400, 'MISSING_FIELDS', 'Missing fields', null, errors));
        }

        validateFieldsValues(attributes)
        .then(()=> {
            resolve()
        })
        .catch((err)=> {
            reject(err);
        });
    });
}

var NAME_REGEX = /^[a-zA-Z\u00C0-\u017F -]*$/;

function validateFieldsValues(attributes) {
    return new Promise((resolve, reject) => {

        if (attributes.hasOwnProperty('gender')) {
            if (typeof(attributes.gender) !== 'string' || !attributes.gender.match(/(male|female|other)/)) {
                reject(apiErrorHelper.buildError(400, 'UNKNOWN_GENDER', 'Unknown gender \'' + attributes.gender + '\' should one of the following (male|female|other)'));
                return;
            }
        }

        if (attributes.hasOwnProperty('date_of_birth')) {
            if (typeof(attributes.date_of_birth) === 'string' && !isDateFormat(attributes.date_of_birth, dateFormat)) {
                reject(apiErrorHelper.buildError(400, 'MALFORMED_DATE_OF_BIRTH', 'Cannot parse data of birth from  \'' + attributes.date_of_birth + '\' with format ' + dateFormat));
                return;
            }
        }

        if (attributes.hasOwnProperty('lastname')) {
            if (typeof(attributes.lastname) !== 'string' || !attributes.lastname.match(NAME_REGEX)) {
                reject(apiErrorHelper.buildError(400, 'INVALID_LAST_NAME', 'Invalid lastname \'' + attributes.lastname + '\' not verified by following reg exp ' + NAME_REGEX));
                return;
            }
        }
        if (attributes.hasOwnProperty('firstname')) {
            if (typeof(attributes.firstname) !== 'string' || !attributes.firstname.match(NAME_REGEX)) {
                reject(apiErrorHelper.buildError(400, 'INVALID_FIRST_NAME', 'Invalid firstname \'' + attributes.lastname + '\' not verified by following reg exp ' + NAME_REGEX));
                return;
            }
        }

        resolve();
    });
}
