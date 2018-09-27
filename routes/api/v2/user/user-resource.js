"use strict";

const cors = require('../../../../lib/cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models/index');
var auth = require('basic-auth');
var jwtHelper = require('../../../../lib/jwt-helper');
var _ = require('underscore');

var delete_user = function (req, res) {
    logger.debug('[API-V2][User][DELETE]');

    var user = auth(req);

    if (!user) {
        return res.json({error: 'missing credentials'}).status(400).send();
    } else {
        var login = user.name;
        var password = user.pass;


        db.LocalLogin.findOne({where: {login: login}}).then(function (localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password)
                    .then(function (isMatch) {
                        logger.info('isMatch', isMatch);
                        if (isMatch) {
                            // Transactional part
                            return db.sequelize.transaction(function (transaction) {
                                return db.LocalLogin.destroy({
                                    where: {user_id: localLogin.user_id},
                                    transaction: transaction
                                }).then(function () {
                                    return db.SocialLogin.destroy({
                                        where: {user_id: localLogin.user_id},
                                        transaction: transaction
                                    });
                                }).then(function () {
                                    return db.User.destroy({
                                        where: {id: localLogin.user_id},
                                        transaction: transaction
                                    });
                                }).then(function () {
                                    return res.status(204).send();
                                });
                            });
                        } else {
                            return res.status(401).send();
                        }
                    });
            }
        });
    }
};

var get_user_id = function (req, res) {
    var auth = req.headers.authorization;
    if (!auth) {
        return res.status(401).send({error: 'missing header Authorization'});
    } else {
        if (auth.indexOf("Bearer ") == 0) {
            var token = auth.substring("Bearer ".length);
            try {
                let userId = jwtHelper.decode(token).id;
                return res.status(200).send({id: userId});
            } catch (err) {
                return res.status(401).send({error: 'Cannot parse JWT token'});
            }
        } else {
            return res.status(401).send({error: 'Authorization doesn\'t have the expect format "Bearer [token]"'});
        }
    }

};

var get_user = function (req,res) {
    if (!req.headers.authorization) {
        return res.status(401).send({error: 'missing header Authorization'});
    } else {
        var user = auth(req);
        var login = user.name;
        var password = user.pass;
        db.LocalLogin.findOne({where: {login: login}})
        .then(function (localLogin) {
            if (!localLogin) {
                logger.info('locallogin not found');
                return res.status(401).send();
            } else {
                return localLogin.verifyPassword(password)
                .then(function (isMatch) {
                    logger.info('isMatch', isMatch);
                    if (isMatch) {
                        db.User.findOne({
                            where: {id: localLogin.user_id},
                            include: [db.Permission]
                        })
                        .then(function (user) {
                            // be sure about what we send? here we go.
                            res.json({user: _.pick(user,'id','display_name','photo_url','firstname','lastname','gender','language','permission_id')});
                        })
                        .catch(function (error) {
                            logger.error(error);
                            res.sendStatus(500);
                        });
                    } else {
                        logger.debug("Authentication failed for " + user.name);
                        res.sendStatus(401);
                    }
                });
            }
        });
    }
};

module.exports = function (router) {

    /**
     * @swagger
     * /api/v2/basicauth/user:
     *   delete:
     *     description: delete the user providing user credentials
     *     operationId: "deleteUser"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "user credentials basic authentication format AKA base64 applied to login+':'+password prefixed by 'Basic '"
     *            required: true
     *            schema:
     *              type: string
     *              example: Basic bG9naW46cGFzc3dvcmQ=
     *     responses:
     *          "204":
     *            description: "user had been deleted"
     *   get:
     *     description: get a users profile by credentials
     *     operationId: "getUser"
     *     content:
     *       - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "user credentials basic authentication format AKA base64 applied to login+':'+password prefixed by 'Basic '"
     *            required: true
     *            schema:
     *              type: string
     *              example: Basic bG9naW46cGFzc3dvcmQ=
     *     responses:
     *          "200":
     *            description: "user profile including permissions in json body"
     */

    router.delete('/api/v2/basicauth/user', cors, delete_user);
    router.options('/api/v2/basicauth/user', cors);

    /**
     * @swagger
     * /api/v2/jwt/user/id:
     *   get:
     *     description: retreive user id from jwt token (id is retrieved in jwt token not from the database)
     *     operationId: "getUserId"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "jwt token"
     *            required: true
     *            schema:
     *              type: string
     *              example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c=
     *     responses:
     *          "200":
     *            description: "user had been deleted"
     *            schema:
     *              type: string
     *              example: 42b
     */
    router.get('/api/v2/jwt/user/id', cors, get_user_id);
    router.options('/api/v2/jwt/user/id', cors);

    router.get('/api/v2/basicauth/user/profile', cors, get_user);
};
