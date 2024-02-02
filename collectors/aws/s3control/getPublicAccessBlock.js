const {
    S3Control
} = require('@aws-sdk/client-s3-control');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var s3control = new S3Control(AWSConfig);

    var accountId = collection.sts.getCallerIdentity[AWSConfig.region].data;
    collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId] = {};

    var params = {
        AccountId: accountId
    };

    helpers.makeCustomCollectorCall(s3control, 'getPublicAccessBlock', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].err = err;
        }
        collection.s3control.getPublicAccessBlock[AWSConfig.region][accountId].data = data;
        callback();
    });
};