var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {

    var wafv2 = new AWS.WAFV2(AWSConfig);

    if (!collection.sts.getCallerIdentity || !collection.sts.getCallerIdentity['us-east-1'].data) return callback();
    
    async.eachLimit(collection.cognitoidentityserviceprovider.listUserPools[AWSConfig.region].data, 15, function(up, cb){
        collection.wafv2.getWebACLForCognitoUserPool[AWSConfig.region][up.Id] = {};
        var params = {
            'ResourceArn':`arn:aws:cognito-idp:${AWSConfig.region}:${collection.sts.getCallerIdentity['us-east-1'].data}:userpool/${up.Id}`
        };

        helpers.makeCustomCollectorCall(wafv2, 'getWebACLForResource', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.wafv2.getWebACLForCognitoUserPool[AWSConfig.region][up.Id].err = err;
            }
            collection.wafv2.getWebACLForCognitoUserPool[AWSConfig.region][up.Id].data = data;
            cb();
        });

    }, function(){
        callback();
    });
};