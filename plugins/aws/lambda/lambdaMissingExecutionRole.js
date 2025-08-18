var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Missing Execution Role',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'High',
    description: 'Ensure that all AWS Lambda functions have an assigned execution role to operate securely and successfully.',
    more_info: 'An execution role provides the permissions a Lambda function needs to access AWS services and resources. Functions without execution roles cannot access other AWS services.',
    link: 'https://www.trendmicro.com/cloudoneconformity/knowledge-base/aws/Lambda/referencing-missing-execution-role.html',
    recommended_action: 'Modify the Lambda function and assign an execution role.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunction', 'IAM:getRole'],
    realtime_triggers: [
        'lambda:CreateFunction',
        'lambda:UpdateFunctionConfiguration',
        'lambda:DeleteFunction',
        'iam:RemoveRole',
        'iam:AddRole',
        'iam:UpdateRole'
    ],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb) {
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();

            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            async.each(listFunctions.data, function(lambdaFunction, cb) {
                if (!lambdaFunction.FunctionName) return cb();

                var getFunction = helpers.addSource(cache, source,
                    ['lambda', 'getFunction', region, lambdaFunction.FunctionName]);

                if (!getFunction || getFunction.err || !getFunction.data || !getFunction.data.Configuration) {
                    helpers.addResult(results, 3,
                        `Unable to get Lambda function details: ${helpers.addError(getFunction)}`,
                        region, lambdaFunction.FunctionArn);
                    return cb();
                }

                var lambdaConfig = getFunction.data.Configuration;
                
                if (!lambdaConfig.Role) {
                    helpers.addResult(results, 2,
                        'Lambda function does not have an execution role assigned',
                        region, lambdaFunction.FunctionArn);
                } else {
                    var getRole = helpers.addSource(cache, source,
                        ['iam', 'getRole',region, lambdaConfig.Role]);

                    if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                        helpers.addResult(results, 2,
                            `Lambda function execution role "${lambdaConfig.Role}" does not exist`,
                            region, lambdaFunction.FunctionArn);
                    } else {
                        helpers.addResult(results, 0,
                            'Lambda function has a valid execution role assigned',
                            region, lambdaFunction.FunctionArn);
                    }
                }
                
                cb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};