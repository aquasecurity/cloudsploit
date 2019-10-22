var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketLogging', false, AWSConfig, collection, callback);
};