var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Collection Public Access',
    category: 'OpenSearch',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensures that OpenSearch Serverless collections are not publicly accessible.',
    more_info: 'OpenSearch Serverless collections should be not be publicly accessible to prevent unauthorized actions.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-network.html',
    recommended_action: 'Update the network policy and remove the public access to the collection.',
    apis: ['OpenSearchServerless:listNetworkSecurityPolicies', 'OpenSearchServerless:getNetworkSecurityPolicy', 'OpenSearchServerless:listCollections'],
    realtime_triggers: ['opensearchserverless:CreateCollection', 'opensearserverless:UpdateCollection', 'opensearchserverless:DeleteCollection'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.opensearchserverless, function(region, rcb){
            var listCollections = helpers.addSource(cache, source, 
                ['opensearchserverless', 'listCollections', region]);
            
            if (!listCollections) return rcb();

            if ( !listCollections.data || listCollections.err) {
                helpers.addResult(results, 3,
                    'Unable to query list OpenSearch collections: ' + helpers.addError(listCollections), region);
                return rcb();
            }

            if (!listCollections.data.length){
                helpers.addResult(results, 0, 'No OpenSearch collections found', region);
                return rcb();
            }
            var listSecurityPolicies = helpers.addSource(cache, source,
                ['opensearchserverless', 'listNetworkSecurityPolicies', region]);

            if (!listSecurityPolicies && listSecurityPolicies.err || !listSecurityPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to list OpenSearch security policies: ' + helpers.addError(listSecurityPolicies), region);
                return rcb();
            }


            let policyMap = {};
            for (let policy of listSecurityPolicies.data){
                var getSecurityPolicy = helpers.addSource(cache, source,
                    ['opensearchserverless', 'getNetworkSecurityPolicy', region, policy.name]);

                if (getSecurityPolicy && getSecurityPolicy.data && getSecurityPolicy.data.securityPolicyDetail &&  getSecurityPolicy.data.securityPolicyDetail.policy){
                    for (let collection of listCollections.data){
                        for (let p of getSecurityPolicy.data.securityPolicyDetail.policy){
                            if (p.AllowFromPublic){
                                let found = p.Rules.find(rule => rule.Resource.indexOf(`collection/${collection.name}`) > -1 &&
                                    rule.ResourceType == 'collection');

                                if (found && !policyMap[collection.arn]){
                                    policyMap[collection.arn] = policy.name;
                                    break;
                                }
                            }
                        }
                    }
                }
            }

            for (let col of listCollections.data){
                if (policyMap[col.arn]){
                    helpers.addResult(results, 2, 'OpenSearch collection is publicly accessible', region, col.arn);
                } else {
                    helpers.addResult(results, 0, 'OpenSearch collection is not publicly accessible', region, col.arn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
