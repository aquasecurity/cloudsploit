var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Function URL Not in Use',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensure that AWS Lambda functions are not configured with function URLs for HTTP(S) endpoints.',
    more_info: 'A function URL creates a direct HTTP(S) endpoint to your function and this may pose a security risk depending on the security configuration and intention of the function.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html',
    recommended_action: 'Modify Lambda function configurations and delete function url',
    apis: ['Lambda:listFunctions','Lambda:listFunctionUrlConfigs'],
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration','lambda:DeleteFunction'],

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
            for (var lambdaFunc of listFunctions.data) {
                if (!lambdaFunc.FunctionName) continue;
                var resource = lambdaFunc.FunctionName;
                var urlConfigs = helpers.addSource(cache, source, ['lambda', 'listFunctionUrlConfigs', region, resource]);
                
                if (urlConfigs && urlConfigs.data && urlConfigs.data.FunctionUrlConfigs && urlConfigs.data.FunctionUrlConfigs.length){
                    helpers.addResult(results, 2, 'Lambda function Url is configured', region, resource);
                } else {
                    helpers.addResult(results, 0, 'Lambda function Url is not configured', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
