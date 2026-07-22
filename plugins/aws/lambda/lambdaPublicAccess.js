var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Public Access',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'High',
    description: 'Ensures Lambda functions are not accessible globally',
    more_info: 'The Lambda function execution policy should not allow public invocation of the function.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html',
    recommended_action: 'Update the Lambda policy to prevent access from the public.',
    apis: ['Lambda:listFunctions', 'Lambda:getPolicy', 'STS:getCallerIdentity'],
    settings: {
        lambda_policy_condition_keys: {
            name: 'Lambda Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that restrict wildcard principals i.e. aws:SourceAccount.',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceAccount,aws:SourceArn,aws:SourceOwner'
        }
    },
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration','lambda:AddPermission', 'lambda:RemovePermission','lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var allowedConditionKeys = (settings.lambda_policy_condition_keys ||
            this.settings.lambda_policy_condition_keys.default).split(',');

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            for (var f in listFunctions.data) {
                var func = listFunctions.data[f];
                var arn = func.FunctionArn;

                var policy = helpers.addSource(cache, source,
                    ['lambda', 'getPolicy', region, func.FunctionName]);

                var result = [0, ''];

                if (!policy) {
                    result = [3, 'Error querying for policy for function'];
                } else if (policy.err) {
                    if (policy.err.code && policy.err.code == 'ResourceNotFoundException') {
                        result = [0, 'Function does not have an access policy'];
                    } else {
                        result = [3, 'Error querying for Lambda function policy: ' + helpers.addError(policy)];
                    }
                } else if (policy.data) {
                    var normalized = helpers.normalizePolicyDocument(policy.data.Policy);

                    var found = [];
                    for (var n in normalized) {
                        var statement = normalized[n];
                        if (statement.Condition &&
                            helpers.isValidCondition(statement, allowedConditionKeys,
                                helpers.IAM_CONDITION_OPERATORS, false, accountId, settings)) continue;

                        if (statement.Effect && statement.Effect === 'Allow' &&
                            statement.Principal &&
                            helpers.globalPrincipal(statement.Principal, settings)) {
                            var actions = statement.Action;
                            if (!Array.isArray(actions)) actions = [actions];
                            for (var action of actions) {
                                if (found.indexOf(action) === -1) found.push(action);
                            }
                        }
                    }

                    if (found.length) {
                        result = [2, 'Function policy allows global access to actions: ' + found.join(', ')];
                    } else {
                        result = [0, 'Function policy does not allow global access'];
                    }
                } else {
                    result = [3, 'Unable to obtain Lambda function policy'];
                }

                helpers.addResult(results, result[0], result[1], region, arn);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
