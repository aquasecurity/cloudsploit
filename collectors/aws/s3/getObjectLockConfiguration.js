var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var s3 = new AWS.S3(AWSConfig);

    async.eachLimit(collection.cloudtrail.describeTrails[AWSConfig.region].data, 15, function(ct, cb){        
        var params = {
            'BucketName':[ct.s3BucketName]
        };

        s3.getObjectLockConfiguration(params, function(err, data) {
            collection.s3.getObjectLockConfiguration[AWSConfig.region][ct.s3BucketName] = {};
            if (err || !data) {
                collection.s3.getObjectLockConfiguration[AWSConfig.region][ct.s3BucketName].err = err;
            } else {
                collection.s3.getObjectLockConfiguration[AWSConfig.region][ct.s3BucketName].data = data;
            }
            cb();
        });

    }, function(){
        callback();
    });
};
