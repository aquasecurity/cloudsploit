var index = require(__dirname + '/index.js');

module.exports = function(AWSConfig, collection, callback) {
    index('getBucketVersioning', false, AWSConfig, collection, callback);
};