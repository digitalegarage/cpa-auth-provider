"use strict";

var db = require('../../models');
var config = require('../../config');
var requestHelper = require('../../lib/request-helper');
var passport = require('passport');
var cors = require('../../lib/cors');

var jwtHelpers = require('../../lib/jwt-helper');

module.exports = function (app, options) {

    app.get('/api/local/profile', cors, passport.authenticate('jwt', {session: false}), function (req, res) {
        var token = jwtHelpers.getToken(req.headers);
        if (token) {
            var decoded = jwtHelpers.decode(token, config.jwtSecret);
            db.UserProfile.findOrCreate({
                user_id: decoded.id
            }).then(function (user_profile) {
                if (!user_profile) {
                    return res.status(403).send({msg: 'Authentication failed. user profile not found.'}); //TODO change 401 UNAUTHORIZED
                } else {
                    res.json({
                        success: true,
                        user_profile: {
                            firstName: user_profile.firstName,
                            lastName: user_profile.lastName,
                            gender: user_profile.gender,
                            date_of_birth: user_profile.date_of_birth
                        }
                    });
                }
            });
        } else {
            return res.status(403).send({msg: 'No token provided.'});
        }
    });

    app.post('/api/local/profile', cors, passport.authenticate('jwt', {session: false}), function (req, res) {

        console.log(req.body);


        var token = jwtHelpers.getToken(req.headers);
        if (token) {
            var decoded = jwtHelpers.decode(token, config.jwtSecret);
            db.UserProfile.findOrCreate({
                user_id: decoded.id
            }).then(function (user_profile) {

                    user_profile.updateAttributes(
                        {
                            firstname: req.body.firstname ? req.body.firstname : user_profile.firstName,
                            lastname: req.body.lastname ? req.body.lastname : user_profile.lastname,
                            gender: req.body.gender ? req.body.gender : user_profile.gender,
                            birthdate: req.body.birthdate ? req.body.birthdate : user_profile.birthdate,
                        }
                        )
                        .then(function () {
                                res.json({msg: 'Successfully updated user_profile.'});
                            },
                            function (err) {
                                res.status(500).json({msg: 'Cannot update user_profile. Err:' + err});
                            });
                }
            )


        }

    });

};
