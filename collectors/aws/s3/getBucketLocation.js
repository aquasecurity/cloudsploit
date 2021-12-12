var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, retries, callback) {
    index('getBucketLocation', false, AWSConfig, collection, retries, callback);
};