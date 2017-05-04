var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
	index('getBucketAcl', false, AWSConfig, collection, callback);
};