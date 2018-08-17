"use strict";

var cors = require('cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models/index');
var auth = require('basic-auth');
var jwtHelper = require('../../../../lib/jwt-helper');

var delete_user = function (req, res) {
    logger.debug('[API-V2][User][DELETE]');

    var user = auth(req);
    logger.info('user', user);

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
                logger.info('locallogin', localLogin);
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
                let userId = jwtHelper.getUserId(token);
                return res.status(200).send({id: userId});
            } catch (err) {
                return res.status(401).send({error: 'Cannot parse JWT token'});
            }
        } else {
            return res.status(401).send({error: 'Authorization doesn\'t have the expect format "Bearer [token]"'});
        }
    }

};


module.exports = function (router) {


    // TODO configure the restriction of origins on the CORS preflight call
    var cors_headers = cors({origin: true, methods: ['DELETE']});

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
     */
    router.delete('/api/v2/basicauth/user', cors_headers, delete_user);
    router.options('/api/v2/basicauth/user', cors_headers);

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
    router.get('/api/v2/jwt/user/id', cors_headers, get_user_id);
    router.options('/api/v2/jwt/user/id', cors_headers);


};