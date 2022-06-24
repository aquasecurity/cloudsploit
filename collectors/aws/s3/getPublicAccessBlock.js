var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, retries, callback) {
    index('getPublicAccessBlock', false, AWSConfig, collection, retries, callback);
};