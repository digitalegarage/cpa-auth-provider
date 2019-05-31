"use strict";

var config = require('../config');

function getPath(path) {
    var urlPrefix = config.urlPrefix || '';
    path = urlPrefix + path;
    return path;
}

function getIdpRoot() {
    var urlPrefix = config.urlPrefix || '';
    return config.baseUrl + urlPrefix;
}

/**
 * Returns true if the Content-Type header of the given request matches the
 * given content type.
 */
function isContentType(req, contentType) {
    var actualContentType = req.get('Content-Type');

    return actualContentType && actualContentType.indexOf(contentType) !== -1;
}

function redirect(res, path) {
    path = getPath(path);
    return res.redirect(path);
}


module.exports = {

    isContentType: isContentType,

    redirect: redirect,

    getPath: getPath,

    getIdpRoot: getIdpRoot

};
