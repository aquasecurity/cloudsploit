var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Unique Execution Role',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that AWS Lambda functions do not share the same execution role.',
    more_info: 'An execution role grants required permission to Lambda function to access AWS services and resources. It is recommended to associate the unique IAM role for each Lambda function to follow the principle of least privilege access.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html',
    recommended_action: 'Modify Lambda function and add new execution role.',
    apis: ['Lambda:listFunctions'],
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration', 'lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.lambda, function(region, rcb){
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
            let roleMap = {};
            for (let lambdaFunc of listFunctions.data) {
                if (!lambdaFunc.Role) continue;

                if (roleMap[lambdaFunc.Role]){
                    roleMap[lambdaFunc.Role].push(lambdaFunc.FunctionArn);
                } else {
                    roleMap[lambdaFunc.Role] = [lambdaFunc.FunctionArn];
                }
            }

            for (let lambdaFunc of listFunctions.data) {
                if (!lambdaFunc.FunctionArn) continue;
                
                if (roleMap[lambdaFunc.Role] && roleMap[lambdaFunc.Role].length > 1) {
                    helpers.addResult(results, 2, 'Lambda function does not have unique execution role', region, lambdaFunc.FunctionArn);
                } else {
                    helpers.addResult(results, 0, 'Lambda function have unique execution role', region, lambdaFunc.FunctionArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
