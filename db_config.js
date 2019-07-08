const fs = require('fs');

let dialectOptions = process.env.DB_DIALECT_OPTIONS;

if (dialectOptions) {
    const dopts = JSON.parse(dialectOptions);
    if (dopts.ssl) {
        if (dopts.ssl.key && dopts.ssl.cert && dopts.ssl.ca) {
            dopts.ssl.key = fs.readFileSync(dopts.ssl.key);
            dopts.ssl.cert = fs.readFileSync(dopts.ssl.cert);
            dopts.ssl.ca = fs.readFileSync(dopts.ssl.ca);
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
        "port": process.env.DB_PORT
    },
    "production": {
        "host": process.env.DB_HOST,
        "dialect": process.env.DB_TYPE,
        "dialectOptions": dialectOptions,
        "username": process.env.DB_USER,
        "password": process.env.DB_PASSWORD,
        "database": process.env.DB_DATABASE,
        "port": process.env.DB_PORT
    }
};
