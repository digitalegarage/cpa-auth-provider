'use strict';

module.exports = {
    buildError: buildError,
    buildCause: buildCause
};

/**
 * @swagger
 * definitions:
 *  error:
 *      properties:
 *          error:
 *              type: object
 *              properties:
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
 *                  i18n:
 *                      type: string
 *                      example: blablabla
 *                      description: internationalized error message
 *                  causes:
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
 *                              i18n:
 *                                  type: string
 *                                  example: blablabla
 *                                  description: nternationalized error message
 *                  traceId:
 *                      type: string
 *                      example: https://error-tracking.ebu.io/broadcaster/prod/issues/1234/
 *                      description: an optional trace id to get more information in error tracking system
 *                  data:
 *                      type: object
 *                      example: "{'user_expected_permission' : 'admin'}"
 *                      description: an object to provide additional information
 */



/**
 * build a standard error object
 * @param code: a string that identify the error (ex: INVALID_SIGNUP_DATA)
 * @param hint: developer hint
 * @param i18n: optional i18n message
 * @param causes: an optional list of cause
 * @param traceId: an optional trace id to retrieve some information about the error in an error tracking software (ex: SENTRY)
 * @param data: an optional object to provide additional information (ex: user_expected_permission : admin)
 * @return {{error: {code: *, hint: *}}}
 */
function buildError(code, hint, i18n, causes, traceId, data) {
    let errorObject = {error: {code: code, hint: hint}};
    if (i18n){
        errorObject.i18n = i18n;
    }
    if (causes) {
        errorObject.error.causes = causes;
    } else {
        errorObject.error.causes = [];
    }
    if (traceId) {
        errorObject.error.traceId = traceId;
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
 * @param i18n: optional i18n message
 * @param data: an optional object to provide additional information (ex: password_score:1.5)
 * @return {{code: *}}
 */
function buildCause(code, hint, i18n, data) {
    let cause = {code: code};
    if (hint) {
        cause.hint = hint;
    }
    if (data){
        cause.data = data;
    }
    return cause;
}

