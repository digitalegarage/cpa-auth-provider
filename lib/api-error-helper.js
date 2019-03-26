'use strict';

const TYPE = {
    BAD_FORMAT: "BAD_FORMAT",
    MISSING: "MISSING",
    BAD_FORMAT_OR_MISSING: "BAD_FORMAT_OR_MISSING",
    CUSTOM: "CUSTOM"
};

module.exports = {
    throwError,
    buildError,
    buildFieldError,
    TYPE
};


/**
 * @swagger
 * definitions:
 *  error:
 *      properties:
 *          error:
 *              type: object
 *              properties:
 *                  status:
 *                      type: integer
 *                      example: 400
 *                      description: HTTP error status code
 *                      required: true
 *                  code:
 *                      type: string
 *                      example: INVALID_SIGNUP_DATA
 *                      description: error code. That code is unique for the endpoint. It should be written using capital letters underscore separated and be self explanatory.
 *                      required: true
 *                  hint:
 *                      type: string
 *                      example: signup process requires that user choose a untaken email
 *                      description: an optional hint given to the developer. THIS IS NOT SUPPOSED TO BE RETURNED TO END USER!
 *                      required: true
 *                  message:
 *                      type: string
 *                      example: blablabla
 *                      description: internationalized error message
 *                  errors:
 *                      type: array
 *                      description: list of possible causes when applicable
 *                      items:
 *                          type: object
 *                          properties:
 *                              field:
 *                                  type: string
 *                                  example: email
 *                                  description: field that has an issue
 *                                  required: true
 *                              type:
 *                                  type: string
 *                                  example: BAD_FORMAT
 *                                  description: one of the following value BAD_FORMAT / MISSING / BAD_FORMAT_OR_MISSING / CUSTOM
 *                                  required: true
 *                                  enum: [BAD_FORMAT, MISSING, BAD_FORMAT_OR_MISSING, CUSTOM]
 *                              custom_type:
 *                                  type: string
 *                                  example: OWASP_9
 *                                  description: if type is CUSTOM then custom_type give more information about the error
 *                                  required: false
 *                              hint:
 *                                  type: string
 *                                  example: signup process requires that user choose a untaken email
 *                                  description: an optional hint given to the developer. THIS IS NOT SUPPOSED TO BE RETURNED TO END USER!
 *                              message:
 *                                  type: string
 *                                  example: blablabla
 *                                  description: internationalized error message
 *                              data:
 *                                  type: object
 *                                  example: "{'date_format' : 'mm.dd.yyyy'}"
 *                                  description: an object to provide additional information
 *                  data:
 *                      type: object
 *                      example: "{'user_expected_permission' : 'admin'}"
 *                      description: an object to provide additional information
 */

/**
 * build a standard error object
 * @param status: HTTP error status code (ex: 400)
 * @param code: a string that identify the error (ex: INVALID_SIGNUP_DATA). It should be written using capital letters underscore separated and be self explanatory.
 * @param hint: developer hint
 * @param message: optional i18n message
 * @param errors: an optional list of cause
 * @param data: an optional object to provide additional information (ex: user_expected_permission : admin)
 */
function buildError(status, code, hint, message, errors, data) {
    let error = {};
    error.applicationError = _buildError(status, code, hint, message, errors, data);
    return error;
}

/**
 * throw a standard error
 * @param status: HTTP error status code (ex: 400)
 * @param code: a string that identify the error (ex: INVALID_SIGNUP_DATA). It should be written using capital letters underscore separated and be self explanatory.
 * @param hint: developer hint
 * @param message: optional i18n message
 * @param errors: an optional list of cause
 * @param data: an optional object to provide additional information (ex: user_expected_permission : admin)
 */
function throwError(status, code, hint, message, errors, data) {
    let error = _buildError(status, code, hint, message, errors, data);
    throw new ApplicationError(message, status, error);
}

/**
 * build a standard field error object
 * @param field: field name (ex: email)
 * @param type: issue that was detected on field. Could be BAD_FORMAT / MISSING / BAD_FORMAT_OR_MISSING / CUSTOM
 * @param custom_type: when type is custom it should be specified here
 * @param hint: developer hint
 * @param message: optional i18n message
 * @param data: an optional object to provide additional information (ex: password_score:1.5)
 * @return {{field: *, type: *}}
 */
function buildFieldError(field, type, custom_type, hint, message, data) {
    let errors = {field: field, type: type};
    if (custom_type) {
        errors.custom_type = custom_type;
    }
    if (hint) {
        errors.hint = hint;
    }
    if (message) {
        errors.message = message;
    }
    if (data){
        errors.data = data;
    }
    return errors;
}

// Internal stuff

class ApplicationError extends Error {
    constructor(message, status, error) {
        super();

        this.name = this.constructor.name;

        this.message = message ||
            'Something went wrong. Please try again.';

        this.applicationError = error;
    }
}



function _buildError(status, code, hint, message, errors, data) {
    let errorObject = {error: {status: status, code: code, hint: hint}};
    if (message) {
        errorObject.error.message = message;
    }
    if (errors) {
        errorObject.error.errors = errors;
    } else {
        errorObject.error.errors = [];
    }
    if (data) {
        errorObject.error.data = data;
    }
    return errorObject;
}
