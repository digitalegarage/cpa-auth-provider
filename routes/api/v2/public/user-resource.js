"use strict";

var cors = require('cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models/index');
var auth = require('basic-auth');

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


module.exports = function (router) {


    // TODO configure the restriction of origins on the CORS preflight call
    var cors_headers = cors({origin: true, methods: ['DELETE']});

    /**
     * @swagger
     * /api/v2/public/user:
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
    router.delete('/api/v2/public/user', cors_headers, delete_user);
    router.options('/api/v2/public/use', cors_headers);


};