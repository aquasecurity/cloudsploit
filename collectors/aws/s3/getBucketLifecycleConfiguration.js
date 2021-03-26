var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketLifecycleConfiguration', false, AWSConfig, collection, callback);
};