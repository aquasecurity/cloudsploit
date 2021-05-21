var async = require('async');
const OSS = require('ali-oss');

module.exports = function(callKey, AlibabaConfig, collection, region, callback) {
    var store = new OSS(AlibabaConfig);

    async.eachLimit(collection.oss.listBuckets[region].data, 10, function(bucket, bcb){
        let bucketName = bucket.name;
        collection.oss[callKey][region][bucketName] = {};

        store[callKey](bucketName).then((result) => {
            collection.oss[callKey][region][bucketName].data = result.bucket;
            bcb();
        }, (err) => {
            collection.oss[callKey][region][bucketName].err = err;
            bcb();
        });
    }, function(){
        callback();
    });
};