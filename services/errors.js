const VALIDATION_ERROR = "ValidationError";


module.exports = {
    throwValidationError: throwValidationError,
    VALIDATION_ERROR: VALIDATION_ERROR
};


class ValidationError extends Error {
    constructor(errorData, data) {
        super();
        this.name = VALIDATION_ERROR;
        this.errorData = errorData;
        this.errorData.data = data;
    }
}

function throwValidationError(errorData, data) {
    throw new ValidationError(errorData, data);
}