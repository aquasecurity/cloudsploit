var AWS = require('aws-sdk');

module.exports = function(AWSConfig, collection, callback) {
    var s3control = new AWS.S3Control(AWSConfig);

    var accountId = collection.sts.getCallerIdentity[AWSConfig.region].data;
    collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId] = {};

    var params = {
        AccountId: accountId
    };

    s3control.getPublicAccessBlock(params, function(err, data) {
        if (err) {
            collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].err = err;
        }
        collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].data = data;
        callback();
    });
};