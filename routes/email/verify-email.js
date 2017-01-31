"use strict";

var db = require('../../models/index');
var logger = require('../../lib/logger');
var cors = require('cors');

var APPEND_VERIFY = '?auth=account_created';
var APPEND_DELETE = '?auth=account_removed';

module.exports = routes;

function routes(router) {

	router.options('/email/confirm/:key', cors());
	router.get(
		'/email/confirm/:key',
		function (req, res, next) {
			getTokenAndClient(req.params.key).then(
				function (data) {
					var verifyToken = data;
					var client = data.OAuth2Client;
					var user = data.User;

					var clientId = req.query.client_id;

					if (client.client_id != clientId) {
						return res.status(400).json({success: false, reason: 'MISMATCHED_CLIENT_ID'});
					}

					if (!verifyToken.isAvailable()) {
						return res.status(400).json({success: user.email_verified, reason: 'ALREADY_USED'});
					}

					if (user.email_verified) {
						res.status(200).json({success: true, reason: 'NO_CHANGE'});
						return deleteToken(verifyToken);
					}

					user.email_verified = true;
					return user.save().then(
						function () {
							res.status(200).json({success: true, reason: 'CONFIRMED'});
							return deleteToken(verifyToken);
						}
					).catch(
						function (err) {
							logger.error('[/email/confirm/][FAIL][key', req.params.key, '][err', err, ']');
							return res.status(500).json({success: false, reason: 'INTERNAL'});
						}
					);
				},
				function (err) {
					logger.error('[/email/confirm/][FAIL][key', req.params.key, '][err', err, ']');
					res.status(400).json({success: false, reason: 'BAD_REQUEST'});
				}
			)
		}
	);

	router.get(
		'/email/verify/:key',
		function (req, res, next) {
			getTokenAndClient(req.params.key).then(
				function (data) {
					var verifyToken = data;
					var client = data.OAuth2Client;
					var user = data.User;
					var redirect_url = getEmailRedirectUrl(verifyToken, client);
					user.email_verified = true;
					return user.save().then(
						function () {
							if (redirect_url) {
								logger.debug('[email verify][REDIRECT][url', redirect_url, ']');
								res.redirect(redirect_url + APPEND_VERIFY + '&username=' + encodeURIComponent(user.email));
								return deleteToken(verifyToken);//req.params.key);
							} else {
								res.render('./email/verify.ejs', {
									user: user,
									forward_address: 'http://beta.mediathek.br.de'
								});
								return deleteToken(verifyToken);//req.params.key);
							}
						},
						function (err) {
							logger.error('[email verify][RENDER][user_id', verifyToken.user_id, '][error', err, ']');
						}
					);
				},
				function (err) {
					return next(err);
				}
			)
		}
	);

	router.get(
		'/email/delete/:key',
		function (req, res, next) {
			getTokenAndClient(req.params.key).then(
				function (data) {
					var verifyToken = data;
					var client = data.OAuth2Client;
					var user = data.User;

					var redirect_url = getEmailRedirectUrl(verifyToken, client);
					if (redirect_url) {
						res.redirect(redirect_url + APPEND_DELETE + '&username=' + encodeURIComponent(user.email));
					} else {
						res.render('./email/delete.ejs', {
							user: user,
							forward_address: 'http://beta.mediathek.br.de'
						});
					}
					deleteUser(user).then(
						function () {
							deleteToken(verifyToken);
						},
						function () {
						}
					);
				},
				next
			);
		}
	);
}

/** extract and generate proper url for a redirect */
function getEmailRedirectUrl(verifyToken, client) {
	if (client) {
		return client.email_redirect_uri;
	} else {
		return undefined;
	}
}

/** retrieve the token for the key */
function getTokenAndClient(key) {
	return new Promise(
		function (resolve, reject) {
			db.UserEmailToken.find({where: {key: key}, include: [db.User, db.OAuth2Client]}).then(
				function (verifyToken) {
					if (!verifyToken) {
						return reject(new Error('invalid token'));
					}
					resolve(verifyToken);
					// if (verifyToken.oauth2_client_id) {
					// 	db.OAuth2Client.find({where: {id: verifyToken.oauth2_client_id}}).then(
					// 		function (client) {
					// 			resolve({token: verifyToken, client: client});
					// 		},
					// 		function (e) {
					// 			resolve({token: verifyToken, client: undefined});
					// 		}
					// 	);
					// } else {
					// 	resolve({token: verifyToken, client: undefined});
					// }
				},
				reject
			)
		}
	);
}

function getUser(user_id) {
	return new Promise(
		function (resolve, reject) {
			db.User.find({where: {id: user_id}}).then(
				function (user) {
					if (!user) {
						return reject(new Error('user does not exist'));
					} else {
						return resolve(user);
					}
				},
				reject
			)
		}
	);
}

/** remove user-verify-token */
function deleteToken(verifyToken) {//key) {
	verifyToken.consume().then(
		function () {
			logger.debug('[verify token consume][SUCCESS][key', verifyToken.key, '][user_id', verifyToken.user_id, ']');
		},
		function (e) {
			logger.error('[verify token consume][FAIL][key', verifyToken.key, '][user_id', verifyToken.user_id, '][error', e, ']');
		}
	);
}

/** destroys an user */
function deleteUser(user) {
	return new Promise(
		function (resolve, reject) {
			user.destroy().then(
				function () {
					logger.debug('[user delete][SUCCESS][id', user.id, '][email', user.email, ']');
					return resolve();
				},
				function (e) {
					logger.error('[user delete][FAIL][id', user.id, '][error', e, ']');
					return reject();
				}
			)
		}
	);
}