var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
	index('getBucketVersioning', true, AWSConfig, collection, callback);
};