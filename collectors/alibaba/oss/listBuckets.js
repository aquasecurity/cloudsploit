const OSS = require('ali-oss');

module.exports = function(AlibabaConfig, collection, region, callback) {
    const store = new OSS(AlibabaConfig);
    collection.oss.listBuckets[region].data = [];

    var execute = function(nextToken) {
        store.listBuckets({
            'max-keys': 1,
            'marker': nextToken
        }).then((result) => {
            callCB(null, result);
        }, (err) => {
            callCB(err);
        });
    };

    var callCB = function(err, data) {
        if (err) {
            collection.oss.listBuckets[region].err = err;
            return callback();
        }
        collection.oss.listBuckets[region].data = collection.oss.listBuckets[region].data.concat(data.buckets);
        if (data.nextMarker) execute(data.nextMarker);
        else return callback();
    };

    execute();
};