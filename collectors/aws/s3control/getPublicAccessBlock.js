var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var s3Control = new AWS.S3Control(AWSConfig);
    async.eachLimit(collection.sts.getCallerIdentity[AWSConfig.region], 15, function(id, cb){        
        collection.s3control.getPublicAccessBlock[AWSConfig.region][id] = {};
        var params = {
            'AccountId': id
        }

        s3Control.getPublicAccessBlock(params, function(err, data) {
            if (err) {
                collection.s3control.getPublicAccessBlock[AWSConfig.region][id].err = err;
            }
            collection.s3control.getPublicAccessBlock[AWSConfig.region][id].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};