var async = require('async');
const OSS = require('ali-oss');

module.exports = function(callKey, AlibabaConfig, collection, region, callback) {
    async.eachLimit(collection.oss.listBuckets[region].data, 10, function(bucket, bcb){
        var localAlibabaConfig = JSON.parse(JSON.stringify(AlibabaConfig));
        if (bucket.region) localAlibabaConfig['region'] = bucket.region;
        var store = new OSS(localAlibabaConfig);
        let bucketName = bucket.name;
        collection.oss[callKey][region][bucketName] = {};

        store[callKey](bucketName).then((result) => {
            if (callKey == 'getBucketPolicy') collection.oss[callKey][region][bucketName].data = (result.policy)?
                result.policy : result;
            else collection.oss[callKey][region][bucketName].data = result.bucket || result;
            bcb();
        }, (err) => {
            collection.oss[callKey][region][bucketName].err = err;
            bcb();
        });
    }, function(){
        callback();
    });
};