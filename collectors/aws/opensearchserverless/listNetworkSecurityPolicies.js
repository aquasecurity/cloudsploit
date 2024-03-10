const {
    OpenSearchServerless
} = require('@aws-sdk/client-opensearchserverless');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var opensearch = new OpenSearchServerless(AWSConfig);
    collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region] = {};
    let params = {
        type: 'network'
    };
    helpers.makeCustomCollectorCall(opensearch, 'listSecurityPolicies', params, retries, null, null, null, function(err, data) {
        if (err) {
            collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region].err = err;
        } else {
            collection.opensearchserverless.listNetworkSecurityPolicies[AWSConfig.region].data = data.securityPolicySummaries;
        }
        callback();
    });
};