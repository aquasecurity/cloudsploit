var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Old Runtimes',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensures Lambda functions are not using out-of-date runtime environments.',
    more_info: 'Lambda runtimes should be kept current with recent versions of the underlying codebase. Deprecated runtimes should not be used.',
    link: 'http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html',
    recommended_action: 'Upgrade the Lambda function runtime to use a more current version.',
    apis: ['Lambda:listFunctions'],
    settings: {
        lambda_runtime_fail: {
            name: 'Lambda Runtime Fail',
            description: 'Return a failing result for lambda runtime before this number of days for their end of life date.',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 0
        }
    },
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration','lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            lambda_runtime_fail: parseInt(settings.lambda_runtime_fail || this.settings.lambda_runtime_fail.default)
        };

        var deprecatedRuntimes = [
            { 'id':'nodejs', 'name': 'Node.js 0.10', 'endOfLifeDate': '2016-10-31' },
            { 'id':'nodejs4.3', 'name': 'Node.js 4.3', 'endOfLifeDate': '2020-03-05' },
            { 'id':'nodejs4.3-edge', 'name': 'Node.js 4.3', 'endOfLifeDate': '2020-03-05' },
            { 'id':'nodejs6.10', 'name': 'Node.js 6.10', 'endOfLifeDate': '2019-08-12' },
            { 'id':'nodejs8.10', 'name': 'Node.js 8.10', 'endOfLifeDate': '2020-03-06' },
            { 'id':'nodejs10.x', 'name': 'Node.js 10.x', 'endOfLifeDate': '2021-07-30' },
            { 'id':'nodejs12.x', 'name': 'Node.js 12', 'endOfLifeDate': '2023-03-31'},
            { 'id':'nodejs14.x', 'name': 'Node.js 14', 'endOfLifeDate': '2023-12-04'},
            { 'id':'nodejs16.x', 'name': 'Node.js 16', 'endOfLifeDate': '2024-06-12'},
            { 'id':'dotnetcore3.1', 'name': '.Net Core 3.1', 'endOfLifeDate': '2023-04-03' },
            { 'id':'dotnetcore2.1', 'name': '.Net Core 2.1', 'endOfLifeDate': '2022-01-05' },
            { 'id':'dotnetcore2.0', 'name': '.Net Core 2.0', 'endOfLifeDate': '2019-05-30' },
            { 'id':'dotnetcore1.0', 'name': '.Net Core 1.0', 'endOfLifeDate': '2019-06-27' },
            { 'id':'dotnet6', 'name': '.Net 6', 'endOfLifeDate': '2024-11-12' },
            { 'id':'dotnet7', 'name': '.Net 7', 'endOfLifeDate': '2024-05-14' },
            { 'id':'python2.7', 'name': 'Python 2.7', 'endOfLifeDate': '2021-07-15' },
            { 'id':'ruby2.5', 'name': 'Ruby 2.5', 'endOfLifeDate': '2021-07-30' },
            { 'id':'ruby2.7', 'name': 'Ruby 2.7', 'endOfLifeDate': '2023-12-07' },
            { 'id':'python3.6', 'name': 'Python 3.6', 'endOfLifeDate': '2022-07-18'},
            { 'id':'python3.7', 'name': 'Python 3.7', 'endOfLifeDate': '2023-12-04'},
            { 'id':'python3.8', 'name': 'Python 3.8', 'endOfLifeDate': '2024-10-14'},
            { 'id':'go1.x', 'name': 'Go 1', 'endOfLifeDate': '2024-01-08'},
            { 'id':'java8', 'name': 'Java 8', 'endOfLifeDate': '2024-01-08'},
        ];

        async.each(regions.lambda, function(region, rcb){
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

            for (var f in listFunctions.data) {
                // For resource, attempt to use the endpoint address (more specific) but fallback to the instance identifier
                var lambdaFunction = listFunctions.data[f];

                if (!lambdaFunction.Runtime) continue;

                var deprecatedRuntime = deprecatedRuntimes.filter((d) => {
                    return d.id == lambdaFunction.Runtime;
                });
                var version = lambdaFunction.Runtime;
                var runtimeDeprecationDate = (deprecatedRuntime && deprecatedRuntime.length && deprecatedRuntime[0].endOfLifeDate) ? Date.parse(deprecatedRuntime[0].endOfLifeDate) : null;
                let today = new Date();
                today = Date.parse(`${today.getFullYear()}-${today.getMonth()+1}-${today.getDate()}`);
                var difference = runtimeDeprecationDate? Math.round((runtimeDeprecationDate - today)/(1000 * 3600 * 24)): null;
                if (runtimeDeprecationDate && today > runtimeDeprecationDate) { 
                    helpers.addResult(results, 2,
                        'Lambda is using runtime: ' + deprecatedRuntime[0].name + ' which was deprecated on: ' + deprecatedRuntime[0].endOfLifeDate,
                        region, lambdaFunction.FunctionArn);
                } else if (difference && config.lambda_runtime_fail >= difference) {
                    helpers.addResult(results, 2,
                        'Lambda is using runtime: ' + version + ' which is deprecating in ' + Math.abs(difference) + ' days',
                        region, lambdaFunction.FunctionArn);
                } else {
                    helpers.addResult(results, 0,
                        'Lambda is running the current version: ' + version,
                        region, lambdaFunction.FunctionArn);
                } 
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
