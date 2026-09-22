var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

// DescribeSMBFileShares accepts at most 10 file share ARNs per request
var MAX_ARNS_PER_CALL = 10;

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    var storagegateway = new AWS.StorageGateway(AWSConfig);

    var arns = collection.storagegateway.listFileShares[AWSConfig.region].data
        .filter(function(share) {
            return share.FileShareType === 'SMB' && share.FileShareARN;
        })
        .map(function(share) {
            return share.FileShareARN;
        });

    var chunks = [];
    for (var i = 0; i < arns.length; i += MAX_ARNS_PER_CALL) {
        chunks.push(arns.slice(i, i + MAX_ARNS_PER_CALL));
    }

    collection.storagegateway.describeSMBFileShares[AWSConfig.region].data = [];

    async.eachLimit(chunks, 5, function(chunk, cb){
        var params = {
            FileShareARNList: chunk
        };

        helpers.makeCustomCollectorCall(storagegateway, 'describeSMBFileShares', params, retries, null, null, null, settings, scanAWSConfig, AWSConfig, function(err, data) {
            if (err) {
                collection.storagegateway.describeSMBFileShares[AWSConfig.region].err = err;
            } else if (data && data.SMBFileShareInfoList && data.SMBFileShareInfoList.length) {
                collection.storagegateway.describeSMBFileShares[AWSConfig.region].data =
                    collection.storagegateway.describeSMBFileShares[AWSConfig.region].data.concat(data.SMBFileShareInfoList);
            }
            cb();
        });
    }, function(){
        callback();
    });
};
