var AWS = require('aws-sdk');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var opensearch = new AWS.OpenSearchServerless(AWSConfig);
    collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region] = {};
    let params = {
        type: 'network'
    };
    helpers.makeCustomCollectorCall(opensearch, 'listSecurityPolicies', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region].err = err;
        } else if (data && data.securityPolicySummaries) {
            collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region].data = data.securityPolicySummaries;
        }
        callback();
    });
};
