const fs = require('fs');

console.log("HELLOOOO");

let dialectOptions = process.env.DB_DIALECT_OPTIONS;

console.log(dialectOptions);

if (dialectOptions) {
    const dopts = JSON.parse(process.env.DB_DIALECT_OPTIONS);
    if (dopts.ssl && (!dopts.ssl.key || !dopts.ssl.cert || !dopts.ca)) {
        console.error("not all cert files");
        process.exit(-1);
    } else {
        dopts.ssl.key = fs.readFileSync(dopts.ssl.key);
        dopts.ssl.cert = fs.readFileSync(dopts.ssl.cert);
        dopts.ssl.ca = fs.readFileSync(dopts.ssl.ca);
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
