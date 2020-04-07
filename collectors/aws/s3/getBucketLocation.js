var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketLocation', false, AWSConfig, collection, callback);
};