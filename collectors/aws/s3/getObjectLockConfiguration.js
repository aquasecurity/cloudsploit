var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    index('getObjectLockConfiguration', false, AWSConfig, collection, retries, settings, scanAWSConfig, callback);
};