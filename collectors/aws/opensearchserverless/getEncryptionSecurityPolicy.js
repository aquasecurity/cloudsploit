 var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.OpenSearchServerless(AWSConfig);
    // console.log(collection)
    async.eachLimit(collection.opensearchserverless.listSecurityPolicies[AWSConfig.region].data, 10, function(policy, cb){
        // console.log(policy)
        collection.opensearchserverless.getEncryptionSecurityPolicy[AWSConfig.region][policy.name] = {};
        var params = {
            name: policy.name,
            type: 'encryption'
        };

        helpers.makeCustomCollectorCall(ecs, 'getSecurityPolicy', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.opensearchserverless.getEncryptionSecurityPolicy[AWSConfig.region][policy.name].err = err;
            }
            collection.opensearchserverless.getEncryptionSecurityPolicy[AWSConfig.region][policy.name].data = data;

            cb();
        });
    }, function(){
        callback();
    });
};