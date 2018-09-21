const VALIDATION_ERROR = "ValidationError";
const BAD_CREDENTIAL_ERROR = "BadCredentialError";


module.exports = {
    throwValidationError: throwValidationError,
    throwBadCredentialError: throwBadCredentialError,
    VALIDATION_ERROR: VALIDATION_ERROR,
    BAD_CREDENTIAL_ERROR: BAD_CREDENTIAL_ERROR
};


class ValidationError extends Error {
    constructor(errorData, data) {
        super();
        this.name = VALIDATION_ERROR;
        this.errorData = errorData;
        this.errorData.data = data;
    }
}

class BadCredentialError extends Error {
    constructor(errorData) {
        super();
        this.errorData = errorData;
        this.name = BAD_CREDENTIAL_ERROR;
    }
}

function throwValidationError(errorData, data) {
    throw new ValidationError(errorData, data);
}

function throwBadCredentialError(errorData) {
    throw new BadCredentialError(errorData);
}