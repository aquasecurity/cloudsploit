var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Code Signing Enabled',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that AWS Lambda functions are configured to use the Code Signing feature.',
    more_info: 'Code signing for AWS Lambda helps to ensure that only trusted code runs in Lambda functions. When you enable code signing for a function, Lambda checks every code deployment and verifies that the code package is signed by a trusted source.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html',
    recommended_action: 'Modify Lambda function configurations and enable code signing.',
    apis: ['Lambda:listFunctions', 'Lambda:getFunctionCodeSigningConfig'],
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
                
                var codeSigningConfig = helpers.addSource(cache, source, 
                    ['lambda', 'getFunctionCodeSigningConfig', region, lambdaFunc.FunctionName]);

                if (!codeSigningConfig || codeSigningConfig.err || !codeSigningConfig.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for Lambda function code signing config: ${helpers.addError(codeSigningConfig)}`, region, resource);
                    continue;
                }

                if (codeSigningConfig && codeSigningConfig.data && codeSigningConfig.data.CodeSigningConfigArn) {
                    helpers.addResult(results, 0, 'Lambda function has code signing config enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Lambda Function does not have code signing config enabled', region, resource);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
