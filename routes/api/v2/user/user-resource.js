"use strict";

const passport = require('passport');
const cors = require('../../../../lib/cors');
const logger = require('../../../../lib/logger');
const db = require('../../../../models/index');
const auth = require('basic-auth');
const jwtHelper = require('../../../../lib/jwt-helper');
const _ = require('underscore');

function delete_user_by_id(userId, res) {
// Transactional part
    return db.sequelize.transaction(function (transaction) {
        return db.LocalLogin.destroy({
            where: {user_id: userId},
            transaction: transaction
        }).then(function () {
            return db.SocialLogin.destroy({
                where: {user_id: userId},
                transaction: transaction
            });
        }).then(function () {
            return db.User.destroy({
                where: {id: userId},
                transaction: transaction
            });
        }).then(function () {
            return res.status(204).send();
        });
    });
}

function delete_user(req, res){
    return delete_user_by_id(req.user.id, res);
}

var delete_user_with_credentials = function (req, res) {
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
                            return delete_user_by_id(localLogin.user_id, res);
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
    if (!req.headers.authorization || !auth(req)) {
        return res.status(401).send({error: 'missing or bad credential in header Authorization'});
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
                            res.json({user: _.pick(user,'id','display_name','firstname','lastname','gender','language','permission_id')});
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
     * definitions:
     *  User:
     *     type: object
     *     properties:
     *         id:
     *             type: integer
     *             example: 42
     *             description: database primary key
     *             required: true
     *         firstName:
     *             type: string
     *             example: John
     *             description: user firstname
     *         lastName:
     *             type: string
     *             example: Doe
     *             description: user lastname
     *         display_name:
     *             type: string
     *             example: John Doe
     *             description: user display name
     *         gender:
     *             type: string
     *             enum: [other, male, female]
     *             example: male
     *             description: user gender
     *         language:
     *             type: string
     *             example: fr
     *             description: user language
     *         permission_id:
     *             type: integer
     *             example: 2
     *             description: user has permission with id
     */

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
     *            schema:
     *              $ref: '#/definitions/User'     */
    router.options('/api/v2/basicauth/user', cors);
    router.delete('/api/v2/basicauth/user', cors, delete_user_with_credentials);
    router.get('/api/v2/basicauth/user', cors, get_user);

    /**
     * @swagger
     * /api/v2/jwt/user:
     *   delete:
     *     description: delete the user providing user credentials
     *     operationId: "deleteUser"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: header
     *            name: "Authorization"
     *            description: "JWT token"
     *            required: true
     *            schema:
     *              type: string
     *              example: JWT blablabla
     *     responses:
     *          "204":
     *            description: "user had been deleted"
     */

    router.delete('/api/v2/jwt/user', cors, passport.authenticate('jwt', {session: false}), delete_user);

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
    router.options('/api/v2/jwt/user/id', cors);
    router.get('/api/v2/jwt/user/id', cors, get_user_id);

};
