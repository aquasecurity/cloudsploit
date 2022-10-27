var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EKS Cluster Has Tags',
    category: 'EKS',
    domain: 'Containers',
    description: 'Ensure that AWS EKS Clusters have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/eks/latest/userguide/eks-using-tags.html',
    recommended_action: 'Modify EKS Cluster and add tags.',
    apis: ['CognitoIdentityServiceProvider:listUserPools', 'WAFV2:getWebACLForResource', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.cognitoidentityserviceprovider, function(region, rcb) {
            var userPools = helpers.addSource(cache, source,
                ['cognitoidentityserviceprovider', 'listUserPools', region]);

            if (!userPools) return rcb();

            if (userPools.err || !userPools.data){
                helpers.addResult(results, 3,  'Unable to query api: ' + helpers.addError(userPools), region);
                return rcb();
            }
            if (!userPools.data.length){
                helpers.addResult(results, 0, 'No User pool found', region);
                return rcb();
            }
            for (let userPool of userPools.data) {
                var webACLResource = helpers.addSource(cache, source,
                    ['wafv2', 'getWebACLForResource', region, userPool.Id]);
              
                if (!webACLResource || webACLResource.err || !webACLResource.data){
                    helpers.addResult(results, 3,
                        'Unable to query for wafv2 api: ' + helpers.addError(webACLResource), region);
                    return rcb();
                }
                var arn = 'arn:' + awsOrGov + ':cognito-idp:' + region + ':' + accountId + ':userpool/' + userPool.Id;
                if (webACLResource.data.WebACL){
                    helpers.addResult(results, 0, 'User pool has WAFV2 enabled', region, arn);
                } else {
                    helpers.addResult(results, 2, 'User pool does not have WAFV2 enabled', region, arn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
