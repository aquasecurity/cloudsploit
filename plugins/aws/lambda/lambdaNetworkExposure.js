var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Network Exposure',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Info',
    description: 'Check if Lambda functions are exposed to the internet.',
    more_info: 'Lambda functions can be exposed to the internet through Function URLs with public access policies or through API Gateway integrations. It\'s important to ensure these endpoints are properly secured.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-urls.html',
    recommended_action: 'Ensure Lambda Function URLs have proper authorization configured and API Gateway integrations use appropriate security measures.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunctionUrlConfig', 'Lambda:getPolicy', 
        'APIGateway:getRestApis','APIGateway:getResources', 'APIGateway:getStages', 'APIGateway:getIntegration', 'ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups', 
        'ELBv2:describeTargetHealth', 'ELBv2:describeListeners', 'EC2:describeSecurityGroups'],
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

            let lambdaELBMap = helpers.getLambdaTargetELBs(cache, source, region);

            for (var lambda of listFunctions.data) {
                if (!lambda.FunctionArn) continue;

                // Get function URL config and policy for Lambda-specific checks
                var getFunctionUrlConfig = helpers.addSource(cache, source,
                    ['lambda', 'getFunctionUrlConfig', region, lambda.FunctionName]);
                
                var getPolicy = helpers.addSource(cache, source,
                    ['lambda', 'getPolicy', region, lambda.FunctionName]);

                let lambdaResource = {
                    functionUrlConfig: getFunctionUrlConfig,
                    functionPolicy: getPolicy,
                    functionArn: lambda.FunctionArn
                };

                let targetingELBs = lambdaELBMap[lambda.FunctionArn] || [];

                let internetExposed = helpers.checkNetworkExposure(cache, source, [], [], targetingELBs, region, results, lambdaResource);

                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2,
                        `Lambda function is exposed to the internet through: ${internetExposed}`,
                        region, lambda.FunctionArn);
                } else {
                    helpers.addResult(results, 0,
                        'Lambda function is not exposed to the internet',
                        region, lambda.FunctionArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}; 