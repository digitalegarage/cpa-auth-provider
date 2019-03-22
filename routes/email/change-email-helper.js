'use strict';

var db = require('../../models/index');
var logger = require('../../lib/logger');
var emailHelper = require('../../lib/email-helper');
var apiErrorHelper = require('../../lib/api-error-helper');
var config = require('../../config');
var uuid = require('uuid');
var finder = require('../../lib/finder');
const Op = db.sequelize.Op;

var STATES = {
    INVALID_TOKEN: 'INVALID_TOKEN',
    MISMATCHED_CLIENT_ID: 'MISMATCHED_CLIENT_ID',
    ALREADY_USED: 'ALREADY_USED',
    ALREADY_SUCCEED: 'ALREADY_SUCCEED',
    EMAIL_ALREADY_TAKEN: 'EMAIL_ALREADY_TAKEN',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
    TOO_MANY_REQUESTS: 'TOO_MANY_REQUESTS'
};

const APPEND_MOVED = '?auth=account_moved';
const CHANGE_CONF = config.emailChange || {};
const VALIDITY_DURATION = CHANGE_CONF.validity || 24 * 60 * 60;
const DELETION_INTERVAL = CHANGE_CONF.deletionInterval || 8 * 60 * 60;
const REQUEST_LIMIT = CHANGE_CONF.requestLimit || 5;
let activeInterval = 0;
startCycle();

module.exports = {
    move_email: move_email,
    change_email: change_email,
    email_moved: email_moved
};


function move_email(req) {
    return new Promise(function(resolve,reject) {
        var localLogin, token;
        var oldEmail, newUsername;
        var redirect;
        return db.UserEmailToken.findOne({
            where: {key: req.params.token},
            include: [db.User]
        })
        .then((token_) => {
            token = token_;
            if (!token || !token.type.startsWith('MOV')) {
                throw new Error(STATES.INVALID_TOKEN);
            }
            redirect = token.redirect_uri;
            newUsername = token.type.substring('MOV$'.length);
            if (!token.isAvailable()) {
                var err = new Error(STATES.ALREADY_USED);
                err.data = {success: newUsername === oldEmail};
                throw err;
            }
            return db.LocalLogin.findOne({where: {user_id: token.user_id}});
        })
        .then((ll) => {
            localLogin = ll;
            oldEmail = localLogin.login;
            return finder.findUserByLocalAccountEmail(newUsername);
        })
        .then((takenLocalLogin) => {
            if (takenLocalLogin) {
                throw new Error(STATES.EMAIL_ALREADY_TAKEN);
            }
            return finder.findUserByLocalAccountEmail(newUsername).then((takenLogin) => {
                if (takenLogin) {
                    throw new Error(STATES.EMAIL_ALREADY_TAKEN);
                }
                return db.LocalLogin.findOne({
                    where: {user_id: token.user_id},
                    include: [db.User]
                }).then((localLogin) => {
                    return db.sequelize.transaction(function(transaction) {
                        return localLogin.updateAttributes({
                            login: newUsername,
                            verified: true
                        }, {transaction: transaction}).then(function() {
                            return localLogin.User.updateAttributes({
                                display_name: newUsername
                            }, {transaction: transaction});
                        });
                    });
                });
            });
        })
        .then(() => {
            if (req.user && req.user.id === token.user_id) {
                req.user.display_name = newUsername;
            }
            return token.consume();
        })
        .then(() => {
            resolve(newUsername);
        })
        .catch((err) => {
            if (err.data && err.data.success){
                resolve(newUsername);
            } else {
                reject({
                    success: err.data && err.data.success,
                    message: err.message,
                    redirect: redirect,
                    newMail: newUsername
                });
            }

        });
    });
}

function change_email(req) {
    return new Promise(function(resolve,reject) {

        var oldUser = req.user;
        var oldLocalLogin;
        var newUsername = req.body.new_email;
        var password = req.body.password;
        var redirect = req.body.use_custom_redirect && req.body.use_custom_redirect + '' === 'true';
        let oldMail = 'unknown';

        if (!oldUser) {
            logger.debug('[POST /api/v2/[security]/user/email/change][FAIL][user_id][from][to', newUsername, ' where old user is ', oldUser, ']');
            apiErrorHelper.throwError(401, 'USER_UNAUTHORIZED','Didn\'t found user in request scope');
            return;
        }

        if (oldUser && oldUser.email) {
            oldMail = oldUser.email;
        } else if (oldUser && oldUser.LocalLogin && oldUser.LocalLogin.login) {
            oldMail = oldUser.LocalLogin.login;
        }
        logger.debug('[POST /api/v2/[security]/user/email/change][user_id', oldUser.id, '][from', oldMail, '][to', newUsername, ']');

        return finder.findUserByLocalAccountEmail(newUsername).then(function(localLogin) {
            if (localLogin) {
                apiErrorHelper.throwError(400, 'EMAIL_ALREADY_TAKEN',newUsername +' is already taken', req.__('CHANGE_EMAIL_API_EMAIL_ALREADY_TAKEN'));
                return;
            }
            // At last check password
            return db.LocalLogin.findOne({where: {user_id: oldUser.id}}).then(function(localLogin) {
                oldLocalLogin = localLogin;
                return localLogin.verifyPassword(password);
            });
        })
        .then((correct) => {
            if (!correct) {
                (apiErrorHelper.throwError(401, 'WRONG_PASSWORD','wrong password', req.__('CHANGE_EMAIL_API_WRONG_PASSWORD')));
                return;
            }
            const validityDate = new Date(new Date().getTime() - VALIDITY_DURATION * 1000);
            return db.UserEmailToken.count({where: {user_id: oldUser.id, created_at: {[Op.gte]: validityDate}}});
        })
        .then((tokenCount) => {
            if (tokenCount >= REQUEST_LIMIT) {
                apiErrorHelper.throwError(429, 'TOO_MANY_REQUESTS','wrong password', req.__('CHANGE_EMAIL_API_TOO_MANY_REQUESTS'));
            }
            logger.debug('[POST /api/v2/[security]/user/email/change][SUCCESS][user_id', oldUser.id, '][from', oldLocalLogin.login, '][to', newUsername, ']');
            triggerAccountChangeEmails(oldLocalLogin.login, oldUser, req.authInfo ? req.authInfo.client : null, newUsername, redirect).then(
                function() {
                    logger.debug('[POST /api/v2/[security]/user/email/change][EMAILS][SENT]');
                },
                function(e) {
                    logger.warn('[POST /api/v2/[security]/user/email/change][EMAILS][ERROR][', e, ']');
                });
            resolve();
        })
        .catch((err) => {
            logger.warn('[POST /api/v2/[security]/user/email/change][FAIL][user_id', oldUser.id, '][from',
                oldUser.email, '][to', newUsername, '][err', err, ']');
            reject(err);
        });
    });
}

function email_moved(req, res) {
    var user, token, localLogin;
    var clientId, oldEmail, newUsername;
    db.UserEmailToken.findOne(
        {
            where: {key: req.params.token},
            include: [db.User, db.OAuth2Client]
        })
    .then((token_) => {
        token = token_;
        clientId = req.query.client_id;
        if (!token || !token.type.startsWith('MOV')) {
            throw new Error(STATES.INVALID_TOKEN);
        }

        if (token.OAuth2Client.client_id !== clientId) {
            throw new Error(STATES.MISMATCHED_CLIENT_ID);
        }

        user = token.User;
        return db.LocalLogin.findOne({where: {user_id: user.id}});
    })
    .then((localLogin_) => {
        localLogin = localLogin_;
        oldEmail = localLogin.login;
        newUsername = token.type.split('$')[1];

        if (!token.isAvailable()) {
            if (oldEmail === newUsername){
                // It seems that user has reopended the validation link. => no error
                throw new Error(STATES.ALREADY_SUCCEED);
            } else {
                throw new Error(STATES.ALREADY_USED);
            }
        }

        return finder.findUserByLocalAccountEmail(newUsername);
    })
    .then((takenUser) => {
        if (takenUser) {
            throw new Error(STATES.EMAIL_ALREADY_TAKEN);
        }
        return finder.findUserBySocialAccountEmail(newUsername);
    })
    .then((socialLogin_)=> {
        if (socialLogin_) {
            throw new Error(STATES.EMAIL_ALREADY_TAKEN);
        }
        return localLogin.updateAttributes({
            login: newUsername,
            verified: true
        });
    })
    .then(()=> {
        return token.consume();
    })
    .then(() => {
        return res.sendStatus(204);
    })
    .catch((err) => {
        if (err.message === STATES.ALREADY_SUCCEED) {
            return res.sendStatus(304);
        }

        logger.error('[GET /email/moved/:token][FAIL][old', oldEmail, '][new', newUsername, '][user.id', user ? user.id : null, '][err', err, ']');

        let status;
        if (err.message === STATES.EMAIL_ALREADY_TAKEN || STATES.MISMATCHED_CLIENT_ID) {
            status = 400;
        } else if (err.message === STATES.ALREADY_USED || err.message === STATES.INVALID_TOKEN) {
            status = 403;
        }
        return res.status(status).json({reason: err.message});
    });
}

function triggerAccountChangeEmails(email, user, client, newUsername, overrideRedirect) {
    return new Promise(
        function(resolve, reject) {
            var redirectUri = client ? client.redirect_uri : undefined;
            const buffer = new Buffer(16);
            uuid.v4({}, buffer);
            var key = buffer.toString('base64');

            db.UserEmailToken.create({
                key: key,
                type: 'MOV$' + newUsername,
                user_id: user.id,
                redirect_uri: redirectUri,
                oauth2_client_id: client ? client.id : undefined
            })
            .then((verifyToken) => {
                    let host = config.mail.host || '';
                    let confirmLink = host + '/api/v2/all/user/email/move/' + encodeURIComponent(key) + '?use_custom_redirect=' + overrideRedirect;
                    if (redirectUri) {
                        confirmLink = redirectUri + APPEND_MOVED + '&username=' + encodeURIComponent(user.email) + '&token=' + encodeURIComponent(key);
                    }

                    logger.debug('send email', confirmLink);
                    return emailHelper.send(
                        config.mail.from,
                        newUsername,
                        'email-change-validation',
                        {},
                        {
                            oldEmail: email,
                            newEmail: newUsername,
                            confirmLink: confirmLink
                        });
                })
            .then(() => {
                    db.LocalLogin.findOne({where: {user_id: user.id}}).then(function(localLogin) {
                        if (localLogin && localLogin.verified) {
                            return emailHelper.send(
                                config.mail.from,
                                localLogin.login,
                                'email-change-information',
                                {},
                                {
                                    oldEmail: email,
                                    newEmail: newUsername
                                });
                        } else {
                            return new Promise(
                                function(resolve, reject) {
                                    return resolve();
                                });
                        }
                    });
                })
            .then(()=> {
                    resolve();
                })
            .catch((err) => {
                reject(err);
            });
        });
}

function cycle() {
    if (DELETION_INTERVAL <= 0) {
        return;
    }

    try {
        const deletionDate = new Date(new Date().getTime() - VALIDITY_DURATION * 1000);
        db.UserEmailToken.destroy(
            {
                where: {
                    created_at: {
                        [Op.lt]: deletionDate
                    }
                }
            })
        .then(count => {
                logger.debug('[EmailChange][DELETE/FAIL][count', count, ']');
            })
        .catch(error => {
                logger.error('[EmailChange][DELETE/FAIL][error', error, ']');
            });
    } catch (e) {
        logger.error('[EmailChange][DELETE/FAIL][error', e, ']');
    }

    activeInterval = setTimeout(cycle, DELETION_INTERVAL * 1000);
}

function startCycle() {
    if (activeInterval) {
        return;
    }
    cycle();
}
