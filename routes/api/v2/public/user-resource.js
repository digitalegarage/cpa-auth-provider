"use strict";

var passport = require('passport');
var cors = require('cors');
var logger = require('../../../../lib/logger');
var db = require('../../../../models/index');

var delete_user = function (req, res) {
    logger.debug('[API-V2][User][DELETE]');
    var login = req.body.login;
    var password = req.body.password;

    db.LocalLogin.findOne({where: {user_id: login}}).then(function (localLogin) {
        if (!localLogin) {
            return res.status(401).send();
        }
        return localLogin.verifyPassword(password);
    }).then(function (isMatch) {
        if (isMatch) {
            // Transactional part
            return db.sequelize.transaction(function (transaction) {
                return localLogin.destroy({
                    where: {user_id: localLogin.user_id},
                    transaction: transaction
                }).then(function () {
                    return db.SocialLogin.destroy({
                        where: {user_id: localLogin.user_id},
                        transaction: transaction
                    });
                }).then(function () {
                    return user.destroy({
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

};


module.exports = function (router) {


    // TODO configure the restriction of origins on the CORS preflight call
    var cors_headers = cors({origin: true, methods: ['DELETE']});

    /**
     * @swagger
     * definition:
     *  Credentials:
     *    properties:
     *      login:
     *          type: string
     *          example: john@doe.com
     *          description: user login
     *          required: true
     *      password:
     *          type: string
     *          example: myCrazyUnbreakableP@ssword
     *          description: user password
     *          required: true
     *
     */

    /**
     * @swagger
     * /api/v2/public/user:
     *   delete:
     *     description: delete the user providing user credentials
     *     operationId: "deleteUser"
     *     content:
     *        - application/json
     *     parameters:
     *          - in: body
     *            name: "Credentials"
     *            description: "user credentials"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/Credentials"
     *     responses:
     *          "204":
     *            description: "user had been deleted"
     */
    router.delete('/api/v2/public/user', cors_headers, delete_user());
    router.options('/api/v2/public/use', cors_headers);


};