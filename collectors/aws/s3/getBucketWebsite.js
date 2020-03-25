var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketWebsite', false, AWSConfig, collection, callback);
};