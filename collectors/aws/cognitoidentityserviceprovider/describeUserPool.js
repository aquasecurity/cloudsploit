var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cognito = new AWS.CognitoIdentityServiceProvider(AWSConfig);

    async.eachLimit(collection.cognitoidentityserviceprovider.listUserPools[AWSConfig.region].data, 15, function(lb, cb){
        collection.cognitoidentityserviceprovider.describeUserPool[AWSConfig.region][lb.Id] = {};
        var params = {
            'UserPoolId':lb.Id
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
