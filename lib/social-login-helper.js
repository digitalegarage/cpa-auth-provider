"use strict";

var db = require('../models');
var jwtHelper = require('../lib/jwt-helper');
var oAuthToken = require('../lib/oauth2-token');

const Op = db.sequelize.Op;

var FB = 'facebook';
var GOOGLE = 'google';
module.exports = {
    performLogin: performLogin,
    findOrCreateSocialLoginUser: findOrCreateSocialLoginUser,
    hasSocialLogin: hasSocialLogin,
    hasLocalLogin: hasLocalLogin,
    getSocialLogins: getSocialLogins,
    getSocialEmails: getSocialEmails,
    buildRemoteProfile: buildRemoteProfile,
    findBySocialAccountEmail:findBySocialAccountEmail,
    FB: FB,
    GOOGLE: GOOGLE
};

function performLogin(profile, socialNetworkName, clientId, done) {
    db.SocialLogin.findOne({
        where: {uid: profile.uid, name: socialNetworkName},
        include: [db.User]
    }).then(function (socialLogin) {
        var user;
        if (!socialLogin) {
            // First we try to find any other login the user might have:
            // Does the user have a local login?
            findByLocalAccountEmail(profile.email).then(function (localLogin) {
                if (localLogin) {
                    user = localLogin.User;
                } else {
                    if (profile.email) {
                        // Does the user have another social login?
                        return findBySocialAccountEmail(profile.email).then(function (socialLogin) {
                            if (socialLogin) {
                                user = socialLogin.User;
                            }
                        });
                    }
                }
            }).then(function () {
                // Transactional part
                return db.sequelize.transaction(function (transaction) {
                    var userPromise;
                    // So, did we find a login?
                    if (!user) {
                        //Very first login
                        userPromise = db.User.create({
                            firstname: profile.first_name,
                            lastname: profile.last_name,
                            gender: profile.gender,
                            date_of_birth: profile.birthday,
                            display_name: profile.display_name
                        }, {transaction: transaction});
                    } else {
                        // fill the profile since it's the very first time
                        userPromise = fillProfile(user, null, profile.first_name, profile.last_name, profile.gender, profile.birthday, transaction);
                    }
                    return userPromise.then(function (_user) {
                        user = _user;
                        return db.SocialLogin.create({
                            name: socialNetworkName,
                            email: profile.email,
                            uid: profile.uid,
                            user_id: user.id,
                            firstname: profile.first_name,
                            lastname: profile.last_name,
                            gender: profile.gender,
                            birthday: profile.birthday
                        }, {transaction: transaction});
                    });
                }).then(function (socialLogin) {
                    return socialLogin.logLogin(user);
                }).then(function () {
                    return buildResponse(user, profile.email, clientId);
                }).then(function (response) {
                    return done(null, response);
                });
            }).catch(function (err) {
                return done(err, null);
            });
        } else {
            // Not a first login: don't update the user profile (as a user I don't want that a field I had emptied is filled again by the social login
            // Transactional part (don't need to start a transaction since only one query is executed
            socialLogin.updateAttributes(
                {
                    email: profile.email,
                    firstname: profile.first_name,
                    lastname: profile.last_name,
                    gender: profile.gender,
                    birthday: profile.birthday
                }).then(function () {
                // Don't need transaction
                socialLogin.logLogin(socialLogin.User);
            }).then(function () {
                return buildResponse(socialLogin.User, profile.email, clientId);
            }).then(function (response) {
                return done(null, response);
            }).catch(
                done
            );
        }
    }, function (error) {
        return done(error, null);
    });
}


function findOrCreateSocialLoginUser(socialNetworkName, email, socialNetworkUUID, displayName, firstname, lastname, gender, date_of_birth) {
    return new Promise(function (resolve, reject) {
        findByLocalAccountEmail(email).then(function (localLogin) {
                if (localLogin) {
                    if (localLogin.verified) {
                        db.SocialLogin.findOne({
                            where: {
                                name: socialNetworkName,
                                user_id: localLogin.user_id
                            }
                        }).then(function (socialLogin) {
                            // Transactional part
                            return db.sequelize.transaction(function (transaction) {
                                var socialLoginPromise;
                                if (!socialLogin) {
                                    socialLoginPromise = db.SocialLogin.create({
                                        name: socialNetworkName,
                                        email: email,
                                        uid: socialNetworkUUID,
                                        user_id: localLogin.user_id,
                                        firstname: firstname,
                                        lastname: lastname,
                                        gender: gender,
                                        birthday: date_of_birth,
                                        social_network: socialNetworkName
                                    }, {transaction: transaction});
                                } else {
                                    socialLoginPromise = socialLogin.updateAttributes({
                                        firstname: firstname,
                                        lastname: lastname,
                                        gender: gender,
                                        birthday: date_of_birth
                                    }, {transaction: transaction});
                                }
                                return socialLoginPromise.then(function () {
                                    return fillProfile(localLogin.User, null, firstname, lastname, gender, date_of_birth, transaction).then(function (user) {
                                        resolve(user);
                                    });
                                });

                            });
                        });
                    } else {
                        return resolve(false);
                    }
                } else {
                    var user;
                    // Search for an existing locallogin
                    db.SocialLogin.findOne({
                        where: {uid: socialNetworkUUID, name: socialNetworkName},
                        include: [db.User]
                    }).then(function (existingSocialLogin) {
                        if (existingSocialLogin) {
                            existingSocialLogin.logLogin(existingSocialLogin.User).then(function () {
                                resolve(existingSocialLogin.User);
                            });
                        } else {
                            // There is no social login for that social network
                            // Does the user have another social login?
                            findBySocialAccountEmail(email).then(function (socialLogin) {
                                if (socialLogin) {
                                    user = socialLogin.User;
                                }
                                return db.sequelize.transaction(function (transaction) {
                                    var userPromise;
                                    // So, did we find a login?
                                    if (!user) {
                                        //Very first login
                                        userPromise = db.User.create({
                                            name: socialNetworkName,
                                            uid: socialNetworkUUID,
                                            display_name: displayName,
                                            firstname: firstname,
                                            lastname: lastname,
                                            gender: gender,
                                            birthday: date_of_birth
                                        }, {transaction: transaction});
                                    } else {
                                        // fill the profile since it's the very first time
                                        userPromise = fillProfile(user, displayName, firstname, lastname, gender, date_of_birth, transaction);
                                    }
                                    return userPromise.then(function (_user) {
                                        user = _user;
                                        return db.SocialLogin.create({
                                            name: socialNetworkName,
                                            email: email,
                                            uid: socialNetworkUUID,
                                            user_id: user.id,
                                            firstname: firstname,
                                            lastname: lastname,
                                            gender: gender,
                                            birthday: date_of_birth
                                        }, {transaction: transaction});
                                    });
                                }).then(function (socialLogin) {
                                    return socialLogin.logLogin(user);
                                }).then(function () {
                                    resolve(user);
                                }).catch(
                                    function (err) {
                                        reject(err);
                                    });
                            });
                        }
                    });


                }
            },
            reject
        );
    });
}

function hasSocialLogin(user) {
    return db.SocialLogin.count({where: {user_id: user.id}}).then(function (count) {
        return count >= 1;
    });
}

function hasLocalLogin(user) {
    return db.LocalLogin.count({where: {user_id: user.id}}).then(function (count) {
        return count >= 1;
    });
}

function getSocialLogins(user) {
    return db.SocialLogin.findAll({where: {user_id: user.id}}).then(function (socialLogins) {
        var toReturn = [];
        if (socialLogins) {
            for (var i = 0; i < socialLogins.length; i++) {
                toReturn.push(socialLogins[i].name);
            }
        }
        return toReturn;
    });
}

function getSocialEmails(user) {
    return db.SocialLogin.findAll({where: {user_id: user.id}}).then(function (socialLogins) {
        var toReturn = [];
        if (socialLogins) {
            for (var i = 0; i < socialLogins.length; i++) {
                if (socialLogins[i].email) {
                    toReturn.push(socialLogins[i].email);
                }
            }
        }
        return toReturn;
    });
}

function fillProfile(user, display_name, firstname, lastname, gender, date_of_birth, transaction) {
    if (!user.display_name && display_name) {
        user.display_name = display_name;
    }
    if (!user.firstname && firstname) {
        user.firstname = firstname;
    }
    if (!user.lastname && lastname) {
        user.lastname = lastname;
    }
    if (!user.gender && gender) {
        user.gender = gender;
    }
    if (!user.date_of_birth && date_of_birth) {
        user.date_of_birth = date_of_birth;
    }
    return user.save({transaction: transaction});
}

function buildRemoteProfile(uid, name, email, first_name, last_name, gender, birthday) {
    return {
        uid: uid,
        display_name: name,
        email: email,
        first_name: first_name,
        last_name: last_name,
        gender: gender,
        birthday: birthday
    };
}


function buildResponse(user, email, clientId) {
    return db.OAuth2Client.findOne({where: {[Op.and]: [{client_id: clientId}, {client_id: {[Op.ne]: null}}, {client_id: {[Op.ne]: ""}}]}}).then(function (client) {
        // At this point it's possible that the client is undefined (for instance if no clientId were passed to the buildResponse function)
        // That is not an issue generateAccessToken handle that.
        return oAuthToken.generateAccessToken(client, user).then(function (token) {
            return {
                success: true,
                user: {
                    firstname: user.firstname,
                    lastname: user.lastname,
                    gender: user.gender,
                    date_of_birth: user.date_of_birth,
                    display_name: user.displayName,
                    email: email
                },
                token: token
            };
        });
    });

}

function findBySocialAccountEmail(email) {
    var where = {[Op.and]: []};
    where[Op.and].push(db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('email')), {[Op.like]: email.toLowerCase()}));
    where[Op.and].push({email: {[Op.ne]: null}});
    where[Op.and].push({email: {[Op.ne]: ''}});
    return db.SocialLogin.findOne({
        where: where,
        include: [db.User]
    })
}

function findByLocalAccountEmail(email){
    return db.LocalLogin.findOne({
        where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), {[Op.like]: email.toLowerCase()}),
        include: [db.User]
    });
}

