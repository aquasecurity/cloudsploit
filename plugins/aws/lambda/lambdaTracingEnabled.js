var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Tracing Enabled',
    category: 'Lambda',
    domain: 'Serverless',
    description: 'Ensures AWS Lambda functions have active tracing for X-Ray.',
    more_info: 'AWS Lambda functions should have active tracing in order to gain visibility into the functions execution and performance.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html',
    recommended_action: 'Modify Lambda functions to activate tracing',
    apis: ['Lambda:listFunctions'],
    settings: {
        lambda_whitelist: {
            name: 'Lambda Functions Whitelisted',
            description: 'A comma-delimited list of known lambda function Function Names that should be whitelisted',
            regex: '^.{1,255}$',
            default: 'Aqua-CSPM-Token-Rotator-Function,-CreateCSPMKeyFunction-,-TriggerDiscoveryFunction-,-GenerateVolumeScanningEx-,-GenerateCSPMExternalIdFu-'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            lambda_whitelist: settings.lambda_whitelist || this.settings.lambda_whitelist.default
        };

        if (config.lambda_whitelist &&
            config.lambda_whitelist.length) {
            config.lambda_whitelist = config.lambda_whitelist.split(',');
        } else {
            config.lambda_whitelist = [];
        }

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
                if (!lambdaFunc.FunctionArn) continue;
                var resource = lambdaFunc.FunctionArn;

                let whitelisted = false;
                if (config.lambda_whitelist.length) {
                    config.lambda_whitelist.forEach(whitelist => {
                        if (lambdaFunc.FunctionName.indexOf(whitelist) > -1) {
                            whitelisted = true;
                        }
                    });
                }

                if (whitelisted) {
                    helpers.addResult(results, 0,
                        'The function ' + lambdaFunc.FunctionName + ' is whitelisted.',
                        region, lambdaFunc.FunctionArn);
                } else {
                    if (lambdaFunc.TracingConfig &&
                        lambdaFunc.TracingConfig.Mode &&
                        lambdaFunc.TracingConfig.Mode.toUpperCase() === 'ACTIVE') {
                        helpers.addResult(results, 0,
                            'Function has active tracing', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Function does not have active tracing', region, resource);
                    }
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
