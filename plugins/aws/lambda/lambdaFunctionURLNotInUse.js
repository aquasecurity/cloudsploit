var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lanbda Function URLs not in use',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Info',
    description: 'Check Lambda Function URL is in use or not.',
    more_info: 'Check whether your Amazon Lambda functions are configured with function URLs for HTTP(S) endpoints. A function URL creates a direct HTTP(S) endpoint to your function and this may pose a security risk depending on the security configuration and intention of the function.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html',
    recommended_action: 'Ensure Lambda Function URLs have proper authorization configured and API Gateway integrations use appropriate security measures.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunctionUrlConfig'],
    realtime_triggers: ['lambda:CreateFunctionUrlConfig', 'lambda:UpdateFunctionUrlConfig', 'lambda:DeleteFunctionUrlConfig',
        'lambda:AddPermission', 'lambda:RemovePermission',
        'apigateway:CreateRestApi', 'apigateway:DeleteRestApi', 'apigateway:UpdateRestApi',
        'apigateway:CreateStage', 'apigateway:DeleteStage', 'apigateway:UpdateStage',
        'apigateway:PutIntegration', 'apigateway:DeleteIntegration'],

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
                    'Unable to query for Lambda functions: ' + helpers.addError(listFunctions), region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            for (var lambda of listFunctions.data) {
                if (!lambda.FunctionArn) continue;

                var getFunctionUrlConfig = helpers.addSource(cache, source,
                    ['lambda', 'getFunctionUrlConfig', region, lambda.FunctionName]);

                if(getFunctionUrlConfig.data){
                    helpers.addResult(results,2,
                        `Lambda function URL is in use`,
                        region, lambda.FunctionArn);
                }
                else{
                    helpers.addResult(results,0,
                        `Lambda function URL is not in use`,
                        region, lambda.FunctionArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
