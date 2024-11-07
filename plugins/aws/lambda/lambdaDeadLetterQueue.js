var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Dead Letter Queue',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensure that AWS Lambda functions are configured to use a Dead Letter Queue.',
    more_info: 'Configuring Dead Letter Queues (DLQs) with lambda functions helps to store discarded events and isolate messages that can\'t be processed correctly. It helps to configure an alarm for any messages moved to a dead-letter queue. They are essential in preserving failed events,debugging and determining why their processing didn\'t succeed.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html#invocation-dlq',
    recommended_action: 'Modify Lambda function configurations and enable dead letter queue.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunctionConfiguration'],
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

                if (!lambdaFunc.FunctionArn || !lambdaFunc.FunctionName) continue;

                var resource = lambdaFunc.FunctionArn;
                
                var functionConfig = helpers.addSource(cache, source, ['lambda', 'getFunctionConfiguration', region, lambdaFunc.FunctionName]);

                if (!functionConfig || functionConfig.err || !functionConfig.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for Lambda function config: ${helpers.addError(functionConfig)}`, region, resource);
                    continue;
                }
         
                if (functionConfig.data && 
                    functionConfig.data.DeadLetterConfig && 
                    functionConfig.data.DeadLetterConfig.TargetArn) {
                    helpers.addResult(results, 0, 'Lambda function has dead letter queue configured', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Lambda function does not have dead letter queue configured', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
