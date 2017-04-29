var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
	index('getBucketLogging', true, AWSConfig, collection, callback);
};