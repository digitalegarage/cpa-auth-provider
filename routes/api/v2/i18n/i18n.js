"use strict";

var config = require('../../../../config');
var authHelper = require('../../../../lib/auth-helper');

var routes = function (router) {

    /**
     * @swagger
     * definitions:
     *  UserLocal:
     *      type: "object"
     *      properties:
     *           language:
     *               type: "string"
     *               example: "fr"
     *               description: "Language based on ISO 639-1 codes"
     */

    /**
     * @swagger
     * /api/v2/i18n/cookie:
     *   post:
     *     description: update unauthenticated user language and store it in a cookie
     *     tags: [Public]
     *     parameters:
     *          - in: body
     *            name: "profile"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/UserLocal"
     *     responses:
     *       201:
     *         description: language had been updated
     *       400:
     *         description: "Missing language in request body"
     *         schema:
     *            $ref: '#/definitions/error'
     */
    router.post('/api/v2/i18n/cookie', function (req, res) {

        if (!req.body.language) {
            apiErrorHelper.throwError(400, 'MISSING_LANGUAGE', 'Missing language in request body');
        }

        res.cookie(config.i18n.cookie_name, req.body.language, {
            maxAge: config.i18n.cookie_duration,
            httpOnly: true
        });

        return res.status(201).send();

    });


    /**
     * @swagger
     * /api/v2/i18n/profile:
     *   post:
     *     description: update unauthenticated user language and store it in a cookie AND user profile
     *     tags: [Session]
     *     parameters:
     *          - in: body
     *            name: "profile"
     *            description: "new profile data"
     *            required: true
     *            schema:
     *              $ref: "#/definitions/UserLocal"
     *     responses:
     *       201:
     *         description: language had been updated
     *       400:
     *         description: "Missing language in request body"
     *         schema:
     *            $ref: '#/definitions/error'
     */
    router.post('/api/v2/i18n/profile', authHelper.ensureAuthenticated, function (req, res, next) {

        if (!req.body.language) {
            apiErrorHelper.throwError(400, 'MISSING_LANGUAGE', 'Missing language in request body');
        }

        res.cookie(config.i18n.cookie_name, req.body.language, {
            maxAge: config.i18n.cookie_duration,
            httpOnly: true
        });

        var user = authHelper.getAuthenticatedUser(req);
        if (!user) {
            res.status(401).send();
        } else {
            return user.updateAttributes({language: req.body.language}).then(function () {
                return res.status(200).send();
            });
        }
    });

};

module.exports = routes;
