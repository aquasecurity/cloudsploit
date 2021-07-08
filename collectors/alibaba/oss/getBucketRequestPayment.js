var index = require(__dirname + '/index.js');

module.exports = function(AlibabaConfig, collection, region, callback) {
    index('getBucketRequestPayment', AlibabaConfig, collection, region, callback);
};