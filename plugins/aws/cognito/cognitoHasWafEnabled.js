var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cognito User Pool WAF Enabled',
    category: 'Cognito',
    domain: 'Identity and Access Management',
    description: 'Ensure that Cognito User Pool has WAF enabled.',
    more_info: 'Enabling WAF allows control over unwanted requests to your hosted UI and Amazon Cognito API service endpoints, allowing or denying traffic based off rules in the Web ACL.',
    link: 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-waf.html',
    recommended_action: '1. Enter the Cognito service. 2. Enter user pools and enable WAF from properties.',
    apis: ['CognitoIdentityServiceProvider:listUserPools', 'WAFV2:getWebACLForCognitoUserPool', 'STS:getCallerIdentity'],

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
                helpers.addResult(results, 3,  'Unable to query Cognito user pools: ' + helpers.addError(userPools), region);
                return rcb();
            }

            if (!userPools.data.length){
                helpers.addResult(results, 0, 'No Cognito user pools found', region);
                return rcb();
            }

            for (let userPool of userPools.data) {
                if (!userPool.Id) continue;
                
                var arn = 'arn:' + awsOrGov + ':cognito-idp:' + region + ':' + accountId + ':userpool/' + userPool.Id;

                var webACLResource = helpers.addSource(cache, source,
                    ['wafv2', 'getWebACLForCognitoUserPool', region, userPool.Id]);
              
                if (!webACLResource || webACLResource.err || !webACLResource.data){
                    helpers.addResult(results, 3,
                        'Unable to get WebACL resource for cognito user pool: ' + helpers.addError(webACLResource), region, arn);
                    continue;
                }
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
