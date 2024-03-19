var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Enable Enhanced Monitoring',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that AWS Lambda functions enhanced monitoring is enabled.',
    more_info: 'Enhanced monitoring Amazon Lambda functions with Amazon CloudWatch Lambda Insights help you to monitor, troubleshoot, and optimize your functions.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/monitoring-insights.html',
    recommended_action: 'Modify Lambda function configurations and enable enhanced monitoring.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunction'],
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
                var functionInfo = helpers.addSource(cache, source, ['lambda', 'getFunction', region, resource]);
                if (functionInfo && functionInfo.data && functionInfo.data.Configuration && functionInfo.data.Configuration.Layers && functionInfo.data.Configuration.Layers[0].Arn) {
                    helpers.addResult(results, 0, 'Lambda functions has enhanced monitoring enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Lambda functions does not have enhanced monitoring enabled', region, resource);

                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
