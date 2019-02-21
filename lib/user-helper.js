var config = require('../config');
var db = require('../models');
var passwordHelper = require('./password-helper');
var codeHelper = require('./code-helper');
var emailHelper = require('./email-helper');
var finder = require('./finder');
var xssFilters = require('xss-filters');
var i18n = require('i18n');
const Op = db.sequelize.Op;



var EXCEPTIONS = {
    EMAIL_TAKEN: 'EMAIL_TAKEN',
    PASSWORD_WEAK: 'PASSWORD_WEAK',
    MISSING_FIELDS: 'MISSING_FIELDS',
    UNKNOWN_GENDER: 'UNKNOWN_GENDER',
    MALFORMED_DATE_OF_BIRTH: 'MALFORMED_DATE_OF_BIRTH',
    INVALID_LAST_NAME: 'INVALID_LAST_NAME',
    INVALID_FIRST_NAME: 'INVALID_FIRST_NAME',
    ACCOUNT_EXISTS: 'ACCOUNT_EXISTS'
};

var requiredFields = {
    "gender": false,
    "date_of_birth": false,
    "firstname": false,
    "lastname": false,
    "language": false
};
var NAME_REGEX = /^[a-zA-Z\u00C0-\u017F -]*$/;

prepareConfig();

module.exports = {
    // createLocalLogin: createLocalLogin,
    addLocalLogin: addLocalLogin,
    getRequiredFields: function () {
        return requiredFields;
    },
    reloadConfig: prepareConfig,
    updateProfileLegacy: updateProfileLegacy,
    updateProfile: updateProfile,
    getUsers: getUsers,
    countUsers: countUsers,
    getDisplayableUser: getDisplayableUser,
    validateProfileUpdateDataLegacy: validateProfileUpdateDataLegacy,
    validateProfileUpdateData: validateProfileUpdateData,
    getUserNameByPublicId: getUserNameByPublicId,
    password_recover: password_recover,
    NAME_REGEX: NAME_REGEX,
    EXCEPTIONS: EXCEPTIONS
};


function prepareConfig() {
    config.userProfiles = config.userProfiles || {};
    config.userProfiles.requiredFields = config.userProfiles.requiredFields || [];

    for (var key in requiredFields) {
        if (requiredFields.hasOwnProperty(key)) {
            requiredFields[key] = config.userProfiles.requiredFields.indexOf(key) >= 0;
        }
    }
}

function validateFiledsValues(attributes) {
    if (attributes.hasOwnProperty('gender')) {
        if (typeof(attributes.gender) !== 'string' || !attributes.gender.match(/(male|female|other)/)) {
            throw new Error(EXCEPTIONS.UNKNOWN_GENDER);
        }
    }

    if (attributes.hasOwnProperty('date_of_birth')) {
        if (typeof(attributes.date_of_birth) === 'string' && !attributes.date_of_birth.match(/\d*/)) {
            throw new Error(EXCEPTIONS.MALFORMED_DATE_OF_BIRTH);
        } else if (typeof(attributes.date_of_birth) !== 'string' && typeof(attributes.date_of_birth) !== 'number') {
            throw new Error(EXCEPTIONS.MALFORMED_DATE_OF_BIRTH);
        }
    }

    if (attributes.hasOwnProperty('lastname')) {
        if (typeof(attributes.lastname) !== 'string' || !attributes.lastname.match(NAME_REGEX)) {
            throw new Error(EXCEPTIONS.INVALID_LAST_NAME);
        }
    }
    if (attributes.hasOwnProperty('firstname')) {
        if (typeof(attributes.firstname) !== 'string' || !attributes.firstname.match(NAME_REGEX)) {
            throw new Error(EXCEPTIONS.INVALID_FIRST_NAME);
        }
    }
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
        var err = new Error(EXCEPTIONS.MISSING_FIELDS, missingFields);
        err.data = {missingFields: missingFields};
        throw err;
    }

    validateFiledsValues(attributes);
    return true;
}

/**
 * add a local login to a user
 * @return a promise.
 * @param user The user.
 * @param email The email to be used for local login creation.
 * @param password The password to be set.
 */
function addLocalLogin(user, email, password) {
    return new Promise(
        function (resolve, reject) {
            if (user && user.LocalLogin && user.LocalLogin.id){
                console.log('<<<<<<<< in addLocalLogin account exists')
                throw new Error(EXCEPTIONS.ACCOUNT_EXISTS);
            }
            var localLogin;
            finder.findUserByLocalAccountEmail(email).then(
                function (dupliateLocalLogin) {
                    if (dupliateLocalLogin) {
                        throw new Error(EXCEPTIONS.EMAIL_TAKEN);
                    }

                    if (!passwordHelper.isStrong(email, password)) {
                        throw new Error(EXCEPTIONS.PASSWORD_WEAK);
                    }

                    return db.sequelize.transaction(function (transaction) {
                        // Code that have to run under a transaction:
                        return db.LocalLogin.create(
                            {user_id: user.id, login: email}, {transaction: transaction}
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
                    });
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
                }
            ).then(
                function () {
                    resolve(user);
                }
            ).catch(
                function (err) {
                    reject(err);
                }
            );
        });
}

function updateProfileLegacy(user, data) {
    return new Promise(
        function (resolve, reject) {
            var fields = ['firstname', 'lastname', 'gender', 'date_of_birth', 'language'];
            var attributes = {};
            fields.forEach(function (key) {
                if (data.hasOwnProperty(key)) {
                    //use XSS filters to prevent users storing malicious data/code that could be interpreted then
                    attributes[key] = xssFilters.inHTMLData(data[key]);
                } else if (requiredFields[key]) {
                    attributes[key] = user[key];
                }
            });

            validateFields(attributes);

            if (attributes.date_of_birth) {
                attributes.date_of_birth_ymd = new Date(parseInt(attributes.date_of_birth));
            }

            if (user.firstname && user.lastname) {
                attributes.display_name = user.firstname + ' ' + user.lastname;
            } else {
                attributes.display_name = _getConnectedEmail(user);
            }
            return user.updateAttributes(attributes).then(
                function () {
                    return resolve(user);
                }
            ).catch(
                reject
            );
        });
}

function updateProfile(user, data) {
    return new Promise(
        function (resolve, reject) {
            var fields = ['firstname', 'lastname', 'gender', 'date_of_birth', 'language'];
            var attributes = {};
            fields.forEach(function (key) {
                if (data.hasOwnProperty(key)) {
                    //use XSS filters to prevent users storing malicious data/code that could be interpreted then
                    attributes[key] = xssFilters.inHTMLData(data[key]);
                } else if (requiredFields[key]) {
                    attributes[key] = user[key];
                }
            });

            validateFields(attributes);

            if (attributes.date_of_birth) {
                attributes.date_of_birth_ymd = attributes.date_of_birth;
                attributes.date_of_birth = new Date(attributes.date_of_birth_ymd).getTime();
            }

            if (attributes.firstname && attributes.lastname) {
                attributes.display_name = attributes.firstname + ' ' + attributes.lastname;
            } else {
                attributes.display_name = _getConnectedEmail(user);
            }

            return user.updateAttributes(attributes).then(
                function () {
                    return resolve(user);
                }
            ).catch(
                reject
            );
        });
}

function password_recover(req, res) {

    if (req.recaptcha.error) {
        res.status(400).json({msg: req.__('API_PASSWORD_RECOVER_SOMETHING_WRONG_RECAPTCHA')});
        return;
    }

    req.checkBody('email', req.__('API_PASSWORD_RECOVER_PLEASE_PASS_EMAIL')).isEmail();

    req.getValidationResult().then(function (result) {
        if (!result.isEmpty()) {
            res.status(400).json({errors: result.array()});
            return;
        }

        db.LocalLogin.findOne({
            where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), req.body.email.toLowerCase()),
            include: [db.User]
        }).then(function (localLogin) {
            if (localLogin) {
                codeHelper.generatePasswordRecoveryCode(localLogin.user_id).then(function (code) {
                    emailHelper.send(
                        config.mail.from,
                        localLogin.login,
                        "password-recovery-email",
                        {log: false},
                        {
                            forceLink: config.mail.host + '/password/edit?email=' + encodeURIComponent(localLogin.login) + '&code=' + encodeURIComponent(code),
                            host: config.mail.host,
                            mail: encodeURIComponent(localLogin.login),
                            code: encodeURIComponent(code)
                        },
                        localLogin.User.language ? localLogin.User.language : i18n.getLocale()
                    ).then(
                        function () {
                        },
                        function (err) {
                        }
                    );
                    return res.sendStatus(204);
                });
            } else {
                return res.status(400).json({msg: req.__('API_PASSWORD_RECOVER_USER_NOT_FOUND')});
            }
        }, function (error) {
            res.status(500).json({success: false, msg: req.__('API_ERROR') + error});
        });
    });
}



var DEFAULT_LIMIT = 20;
var MAX_LIMIT = 100;

function buildSearchOptions(req, adminId) {

    var options;

    // If an id is provided any other parameter are not taken into account.
    if (req.query.id) {
        options = {
            where: {id: req.query.id},
            include: [db.LocalLogin]
        };
        return options;
    }

    var offset = 0;
    if (req.query.offset) {
        offset = req.query.offset;
    }

    var include;// = [db.LocalLogin];


    var user_where = {[Op.and]: []};

    if (req.query.firstname) {
        user_where[Op.and].push(
            db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('firstname')),
                {
                    [Op.like]: '%' + req.query.firstname + '%'
                }));
    }
    if (req.query.lastname) {
        user_where[Op.and].push(
            db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('lastname')),
                {
                    [Op.like]: '%' + req.query.lastname + '%'
                }));
    }
    if (req.query.email) {
        var profile_where = db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')),
            {
                [Op.like]: '%' + req.query.email.toLowerCase() + '%'
            });
        include = [{model: db.LocalLogin, where: profile_where}];
    } else {
        include = [db.LocalLogin];
    }

    // Admin search:
    if (req.query.admin) {
        include.push({model: db.Permission, where: {id: adminId}});
    }

    options = {
        offset: offset,
        where: user_where,
        order: ['firstname'],
        include: include
    };

    return options;
}

// This function is not used since I didn't find a way to use LOWER + LIKE on firstname, lastname and email column
function getUsers(req, adminId) {

    var options = buildSearchOptions(req, adminId);

    var limit = DEFAULT_LIMIT;
    if (req.query.limit) {
        if (req.query.limit <= MAX_LIMIT) {
            limit = req.query.limit;
        } else {
            limit = MAX_LIMIT;
        }
    }
    options.limit = limit;

    return db.User.findAll(options);
}

// This function is not used since I didn't find a way to use LOWER + LIKE on firstname, lastname and email column
function countUsers(req, adminId) {

    var options = buildSearchOptions(req, adminId);

    return db.User.count(options);
}

function getDisplayableUser(users) {
    var toReturn = [];
    var arrayLength = users.length;
    for (var i = 0; i < arrayLength; i++) {
        toReturn.push({
            id: users[i].id,
            email: users[i].LocalLogin ? users[i].LocalLogin.login : undefined,
            permission_id: users[i].permission_id,
            created_at: users[i].LocalLogin ? users[i].LocalLogin.created_at : undefined,
            password_changed_at: users[i].LocalLogin ? users[i].LocalLogin.password_changed_at : undefined,
            last_seen: users[i].last_seen ? users[i].last_seen : undefined,
            firstname: users[i].firstname ? users[i].firstname : '',
            lastname: users[i].lastname ? users[i].lastname : ''

        });
    }
    return toReturn;
}

function validateProfileUpdateDataLegacy(req) {
    if (requiredFields.firstname) {
        req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).notEmpty().matches(NAME_REGEX);
    } else if (req.body.firstname) {
        req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).matches(NAME_REGEX);
    }
    if (requiredFields.lastname) {
        req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).notEmpty().matches(NAME_REGEX);
    } else if (req.body.lastname) {
        req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).matches(NAME_REGEX);
    }
    if (requiredFields.date_of_birth) {
        req.checkBody('date_of_birth', req.__('BACK_PROFILE_UPDATE_DATE_OF_BIRTH_EMPTY_OR_INVALID')).notEmpty().isInt();
    } else if (req.body.date_of_birth) {
        req.checkBody('date_of_birth', req.__('BACK_PROFILE_UPDATE_DATE_OF_BIRTH_EMPTY_OR_INVALID')).isInt();
    }
    if (requiredFields.gender) {
        req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).notEmpty().isIn(['male', 'female', 'other']);
    } else if (req.body.gender) {
        req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).isIn(['male', 'female', 'other']);
    }
    if (requiredFields.language) {
        req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).notEmpty().isAlpha();
    } else if (req.body.language) {
        req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).isAlpha();
    }

    return req.getValidationResult();
}


function validateProfileUpdateData(req) {
    if (requiredFields.firstname) {
        req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).notEmpty().matches(NAME_REGEX);
    } else if (req.body.firstname) {
        req.checkBody('firstname', req.__('BACK_PROFILE_UPDATE_FIRSTNAME_EMPTY_OR_INVALID')).matches(NAME_REGEX);
    }
    if (requiredFields.lastname) {
        req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).notEmpty().matches(NAME_REGEX);
    } else if (req.body.lastname) {
        req.checkBody('lastname', req.__('BACK_PROFILE_UPDATE_LASTNAME_EMPTY_OR_INVALID')).matches(NAME_REGEX);
    }
    if (requiredFields.date_of_birth) {
        req.checkBody('date_of_birth', req.__('BACK_PROFILE_UPDATE_DATE_OF_BIRTH_EMPTY_OR_INVALID')).notEmpty().isValidDate();
    } else if (req.body.date_of_birth) {
        req.checkBody('date_of_birth', req.__('BACK_PROFILE_UPDATE_DATE_OF_BIRTH_EMPTY_OR_INVALID')).isValidDate();
    }
    if (requiredFields.gender) {
        req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).notEmpty().isIn(['male', 'female', 'other']);
    } else if (req.body.gender) {
        req.checkBody('gender', req.__('BACK_PROFILE_UPDATE_GENDER_EMPTY_OR_INVALID')).isIn(['male', 'female', 'other']);
    }
    if (requiredFields.language) {
        req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).notEmpty().isAlpha();
    } else if (req.body.language) {
        req.checkBody('language', req.__('BACK_LANGUAGE_UPDATE_LANGUAGE_EMPTY_OR_INVALID')).isAlpha();
    }

    return req.getValidationResult();
}

function getUserNameByPublicId(puid) {
    return new Promise(function(resolve,reject) {
        db.User.findOne({where: { public_uid: puid }})
        .then(function(user) {
            if (user === null)
                resolve();
            else
                resolve({firstname: user.firstname, lastname: user.lastname});
        })
        .catch(function(e) {
            reject(e);
        });
    });
}


function _getConnectedEmail(user) {
    if (user.LocalLogin && user.LocalLogin.login) {
        return user.LocalLogin.login;
    } else if (user.SocialLogin && user.SocialLogin.email){
        return user.SocialLogin.email;
    } else {
        return;
    }
}
