var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketEncryption', false, AWSConfig, collection, callback);
};