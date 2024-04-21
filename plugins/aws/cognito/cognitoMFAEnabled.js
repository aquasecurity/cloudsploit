var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Cognito User Pool MFA enabled',
    category: 'Cognito',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure that Cognito user pool has MFA enabled.',
    more_info: 'Enabling Multi-factor authentication (MFA) increases security for your app. You can choose SMS text messages or time-based one-time passwords (TOTP) as second factors to sign in your users.',
    link: 'https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html',
    recommended_action: '1. Enter the Cognito service. 2. Enter user pools and enable MFA from sign in experience.',
    apis: ['CognitoIdentityServiceProvider:listUserPools', 'CognitoIdentityServiceProvider:describeUserPool', 'STS:getCallerIdentity'],
    realtime_triggers: ['CognitoIdentityServiceProvider:CreateUserPool','CognitoIdentityServiceProvider:SetUserPoolMfaConfig','cognitoidentityserviceprovider:DeleteUserPool'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
  
        async.each(regions.cognitoidentityserviceprovider, function(region, rcb){
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

                const userPoolArn ='arn:' + awsOrGov + ':cognito-idp:' + region + ':' + accountId + ':userpool/' + userPool.Id;

                var describeUserPool = helpers.addSource(cache, source,
                    ['cognitoidentityserviceprovider', 'describeUserPool', region, userPool.Id]);

                if (!describeUserPool || describeUserPool.err || !describeUserPool.data || !describeUserPool.data.UserPool){
                    helpers.addResult(results, 3,
                        'Unable to describe Cognito user pool: ' + helpers.addError(describeUserPool), region, userPoolArn);
                    continue;
                }

                if (describeUserPool.data.UserPool.MfaConfiguration && describeUserPool.data.UserPool.MfaConfiguration.toUpperCase() == 'ON'){
                    helpers.addResult(results, 0, 'User pool has MFA enabled', region, userPoolArn);
                } else {
                    helpers.addResult(results, 2, 'User pool does not have MFA enabled', region, userPoolArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
