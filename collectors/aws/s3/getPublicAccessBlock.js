var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getPublicAccessBlock', false, AWSConfig, collection, callback);
};