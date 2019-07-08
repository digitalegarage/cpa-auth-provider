const fs = require('fs');

let dialectOptions = process.env.DB_DIALECT_OPTIONS ? JSON.parse(process.env.DB_DIALECT_OPTIONS) : undefined;

if (dialectOptions) {
    if (dialectOptions.ssl) {
        if (dialectOptions.ssl.key && dialectOptions.ssl.cert && dialectOptions.ssl.ca) {
            dialectOptions.ssl.key = fs.readFileSync(dialectOptions.ssl.key);
            dialectOptions.ssl.cert = fs.readFileSync(dialectOptions.ssl.cert);
            dialectOptions.ssl.ca = fs.readFileSync(dialectOptions.ssl.ca);
        } else {
            console.error("not all cert files");
            process.exit(-1);
        }
    }
}

module.exports = {
    "development": {
        "host": process.env.DB_HOST,
        "dialect": process.env.DB_TYPE,
        "dialectOptions": dialectOptions,
        "username": process.env.DB_USER,
        "password": process.env.DB_PASSWORD,
        "database": process.env.DB_DATABASE,
        "port": process.env.DB_PORT,
        "storage": process.env.DB_FILENAME,
        "logging": console.log
    },
    "production": {
        "host": process.env.DB_HOST,
        "dialect": process.env.DB_TYPE,
        "dialectOptions": dialectOptions,
        "username": process.env.DB_USER,
        "password": process.env.DB_PASSWORD,
        "database": process.env.DB_DATABASE,
        "port": process.env.DB_PORT,
        "storage": process.env.DB_FILENAME,
        "logging": console.log

    }
};
