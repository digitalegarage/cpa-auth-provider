var db = require('../models');
const Op = db.sequelize.Op;


module.exports = {

    findUserByLocalAccountEmail: findUserByLocalAccountEmail,
    findUserBySocialAccountEmail: findUserBySocialAccountEmail
};



function findUserByLocalAccountEmail(email) {
    if (!email) {
        return new Promise(function(resolve, reject) {
            resolve(null);
        })
    } else {
        return db.LocalLogin.findOne({
            where: db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('login')), {[Op.like]: email.toLowerCase()}),
            include: [db.User]
        });
    }
}

function findUserBySocialAccountEmail(email) {
    if (!email) {
        return new Promise(function(resolve, reject) {
            resolve(null);
        })
    } else {
        var where = {[Op.and]: []};
        where[Op.and].push(db.sequelize.where(db.sequelize.fn('lower', db.sequelize.col('email')), {[Op.like]: email.toLowerCase()}));
        where[Op.and].push({email: {[Op.ne]: null}});
        where[Op.and].push({email: {[Op.ne]: ''}});
        return db.SocialLogin.findOne({
            where: where,
            include: [db.User]
        });
    }
}
