var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Has Tags',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Low',
    description: 'Ensure that AWS Lambda functions have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-tags.html',
    recommended_action: 'Modify Lambda function configurations and  add new tags',
    apis: ['Lambda:listFunctions', 'ResourceGroupsTaggingAPI:getResources'],
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

            let existingLambdaARNList = [];
            for (var lambdaFunc of listFunctions.data) {
                if (!lambdaFunc.FunctionArn) continue;
                existingLambdaARNList.push(lambdaFunc.FunctionArn);
            }
            if (existingLambdaARNList.length){
                helpers.checkTags(cache, 'Lambda function', existingLambdaARNList, region, results, settings);
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
