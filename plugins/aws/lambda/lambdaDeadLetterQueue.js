var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Dead Letter Queue',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensure that AWS Lambda functions are configured to use a Dead Letter Queue',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-property-function-deadletterqueue.html',
    recommended_action: 'Modify Lambda function configurations and  enable dead letter queue',
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
                if (!lambdaFunc.FunctionName) continue;
                var resource = lambdaFunc.FunctionName;
                var functionConfig = helpers.addSource(cache, source, ['lambda', 'getFunctionConfiguration', region, resource]);
            } 
            if (functionConfig && functionConfig.data && functionConfig.data.DeadLetterConfig && functionConfig.data.DeadLetterConfig.TargetArn) {
                helpers.addResult(results, 0, 'Lambda function has Dead Letter Queue configured', region, resource);
            } else {
                helpers.addResult(results, 2, 'Lambda function does not have Dead Letter Queue configured', region, resource);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
