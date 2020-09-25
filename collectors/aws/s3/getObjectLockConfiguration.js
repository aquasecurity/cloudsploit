var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getObjectLockConfiguration', false, AWSConfig, collection, callback);
};