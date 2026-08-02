const {
    OpenSearchServerless
} = require('@aws-sdk/client-opensearchserverless');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new OpenSearchServerless(AWSConfig);
    async.eachLimit(collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region].data, 10, function(policy, cb){
        collection.opensearchserverless.getNetworkSecurityPolicy[AWSConfig.region][policy.name] = {};
        var params = {
            name: policy.name,
            type: 'network'
        };

        helpers.makeCustomCollectorCall(ecs, 'getSecurityPolicy', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.opensearchserverless.getNetworkSecurityPolicy[AWSConfig.region][policy.name].err = err;
            }

            if (data) collection.opensearchserverless.getNetworkSecurityPolicy[AWSConfig.region][policy.name].data = data;

            cb();
        });
    }, function(){
        callback();
    });
};