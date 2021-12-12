var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, retries, callback) {
    index('getBucketWebsite', false, AWSConfig, collection, retries, callback);
};