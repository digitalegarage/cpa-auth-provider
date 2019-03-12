'use strict';

module.exports = {
    buildError: buildError,
    buildErrors: buildErrors
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
 *                      description: error code
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
 *                              code:
 *                                  type: string
 *                                  example: EMAIL_ALREADY_TAKEN
 *                                  description: error code
 *                                  required: true
 *                              hint:
 *                                  type: string
 *                                  example: signup process requires that user choose a untaken email
 *                                  description: an optional hint given to the developer. THIS IS NOT SUPPOSED TO BE RETURNED TO END USER!
 *                              message:
 *                                  type: string
 *                                  example: blablabla
 *                                  description: nternationalized error message
 *                  data:
 *                      type: object
 *                      example: "{'user_expected_permission' : 'admin'}"
 *                      description: an object to provide additional information
 */



/**
 * build a standard error object
 * @param status: HTTP error status code (ex: 400)
 * @param code: a string that identify the error (ex: INVALID_SIGNUP_DATA)
 * @param hint: developer hint
 * @param message: optional i18n message
 * @param causes: an optional list of cause
 * @param data: an optional object to provide additional information (ex: user_expected_permission : admin)
 * @return {{error: {code: *, hint: *}}}
 */
function buildError(status, code, hint, message, errors, data) {
    let errorObject = {error: {status: status, code: code, hint: hint}};
    if (message){
        errorObject.message = message;
    }
    if (errors) {
        errorObject.error.errors = errors;
    } else {
        errorObject.error.errors = [];
    }
    if (data){
        errorObject.error.data = data;
    }
    return errorObject;
}

/**
 * build a standard cause object
 * @param code: a string that identify the error (ex: EMAIL_ALREADY_TAKEN)
 * @param hint: developer hint
 * @param message: optional i18n message
 * @param data: an optional object to provide additional information (ex: password_score:1.5)
 * @return {{code: *}}
 */
function buildErrors(code, hint, message, data) {
    let errors = {code: code};
    if (message) {
        errors.message = message;
    }
    if (data){
        errors.data = data;
    }
    return errors;
}

