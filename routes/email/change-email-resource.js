'use strict';

var cors = require('cors');
var passport = require('passport');
const changeEmailHelper = require('./legacy-change-email-helper');

module.exports = function(app, options) {

    /*
    *
    * Following endpoints are deprecated (used at BR only)
    *
    */
    
    app.options('/email/change', cors());
    app.post('/email/change', cors(), function(req, res, next) {
            if (!!req.user) {
                return next();
            } else {
                return passport.authenticate('bearer', {session: false})(req, res, next);
            }
        },
        changeEmailHelper.change_email);

    app.get('/email/move/:token', changeEmailHelper.move_email);

    app.options('/email/moved/:token', cors());
    app.get('/email/moved/:token', cors(), changeEmailHelper.email_moved);

};
