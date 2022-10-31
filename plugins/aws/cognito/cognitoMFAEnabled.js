var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cognito User Pool Has MFA enabled',
    category: 'CognitoIdentityServiceProvider',
    domain: 'Identity Service Provider',
    description: 'Ensure that cognito user pool has MFA enabled.',
    more_info: 'Enabling WAF allows control over requests to the load balancer, allowing or denying traffic based off rules in the Web ACL',
    link: 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html',
    recommended_action: '1. Enter the Cognito service. 2. Enter user pools and enable MFA from signin experience ',
    apis: ['CognitoIdentityServiceProvider:listUserPools', 'CognitoIdentityServiceProvider:describeUserPool'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
  
        async.each(regions.cognitoidentityserviceprovider, function(region, rcb){
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
                if (!userPool.Id) continue;

                var describeUserPool = helpers.addSource(cache, source,
                    ['cognitoidentityserviceprovider', 'describeUserPool', region, userPool.Id]);

                if (!describeUserPool || describeUserPool.err || !describeUserPool.data){
                    helpers.addResult(results, 3,
                        'Unable to query for Cognito: ' + helpers.addError(describeUserPool), region);
                    
                    continue;
                }
                if (describeUserPool.data.MfaConfiguration && describeUserPool.data.MfaConfiguration == 'ON'){
                    helpers.addResult(results, 0, 'Cognito has MFA enabled', region, describeUserPool.data.Arn);
                } else {
                    helpers.addResult(results, 2, 'MFA not enabled for cognito', region, describeUserPool.data.Arn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
