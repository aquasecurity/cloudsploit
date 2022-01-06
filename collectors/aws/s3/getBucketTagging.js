var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, retries, callback) {
    index('getBucketTagging', false, AWSConfig, collection, retries, callback);
};
