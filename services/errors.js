const VALIDATION_ERROR = "ValidationError";


module.exports = {
    throwValidationError: throwValidationError,
    VALIDATION_ERROR: VALIDATION_ERROR
};


class ValidationError extends Error {
    constructor(message, data) {
        super(message);
        this.name = VALIDATION_ERROR;
        this.data = data;
    }
}

function throwValidationError(msg, data) {
    throw new ValidationError(msg, data);
}