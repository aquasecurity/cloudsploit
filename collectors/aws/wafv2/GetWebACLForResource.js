var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cognito = new AWS.CognitoIdentityServiceProvider(AWSConfig);
    var wafv2 = new AWS.WAFV2(AWSConfig);
    async.eachLimit(collection.cognitoidentityserviceprovider.describeUserPool[AWSConfig.region].data, 15, function(lb, cb){
        collection.cognitoidentityserviceprovider.describeUserPool[AWSConfig.region][lb.Id] = {};
        var params = {
            'ResourceArn':lb.Id
        };

        helpers.makeCustomCollectorCall(cognito, 'describeUserPool', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.cognitoidentityserviceprovider.describeUserPool[AWSConfig.region][lb.Id].err = err;
            }
            collection.cognitoidentityserviceprovider.describeUserPool[AWSConfig.region][lb.Id].data = data.UserPool;
            cb();
        });

    }, function(){
        callback();
    });
};