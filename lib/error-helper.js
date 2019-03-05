'use strict';

module.exports = {
    buildError: buildError,
    buildCause: buildCause
};

/**
 * build a standard error object
 * @param code: a string that identify the error (ex: INVALID_SIGNUP_DATA)
 * @param causes: an optional list of cause
 * @param traceId: an optional trace id to retrieve some information about the error in an error tracking software (ex: SENTRY)
 * @return {{error: {code: *, causes: *}}}
 */
function buildError(code, hint, causes, traceId) {
    let errorObject = {error: {code: code, hint: hint}};
    if (causes) {
        errorObject.error.causes = causes;
    } else {
        errorObject.error.causes = [];
    }
    if (traceId) {
        errorObject.error.traceId = traceId;
    }
    return errorObject;
}

/**
 *
 * @param code
 * @param hint
 * @return {{code: *}}
 */
function buildCause(code, hint) {
    let cause = {code: code};
    if (hint) {
        cause.hint = hint;
    }
    return cause;
}

