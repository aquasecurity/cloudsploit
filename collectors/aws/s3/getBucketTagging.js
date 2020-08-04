var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketTagging', false, AWSConfig, collection, callback);
};
