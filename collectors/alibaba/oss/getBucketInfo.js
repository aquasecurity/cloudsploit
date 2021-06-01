var index = require(__dirname + '/index.js');

module.exports = function(AlibabaConfig, collection, region, callback) {
    index('getBucketInfo', AlibabaConfig, collection, region, callback);
};