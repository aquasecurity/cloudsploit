var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Cloud Function V2 Old Runtimes',
    category: 'Cloud Functions',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that Cloud Functions V2 are not using deprecated runtime versions.',
    more_info: 'Cloud Functions V2 runtimes should be kept current with recent versions of the underlying codebase. It is recommended to update to the latest supported versions to avoid potential security risks and ensure compatibility.',
    link: 'https://cloud.google.com/functions/docs/concepts/execution-environment',
    recommended_action: 'Modify Cloud Functions V2 to use latest versions.',
    apis: ['functionsv2:list'],
    settings: {
        function_runtime_fail: {
            name: 'Cloud Function V2 Runtime Fail',
            description: 'Return a failing result for Cloud Function V2 runtime before this number of days for their end of life date.',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 0
        }
    },
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            function_runtime_fail: parseInt(settings.function_runtime_fail || this.settings.function_runtime_fail.default)
        };

        var deprecatedRuntimes = [
            { 'id':'nodejs10', 'name': 'Node.js 10.x', 'endOfLifeDate': '2021-07-30' },
            { 'id':'nodejs12', 'name': 'Node.js 12', 'endOfLifeDate': '2024-01-30' },
            { 'id':'nodejs14', 'name': 'Node.js 14', 'endOfLifeDate': '2024-01-30' },
            { 'id':'nodejs16', 'name': 'Node.js 16', 'endOfLifeDate': '2024-01-30' },
            { 'id':'nodejs18', 'name': 'Node.js 18', 'endOfLifeDate': '2025-04-30' },
            { 'id':'nodejs20', 'name': 'Node.js 20', 'endOfLifeDate': '2026-04-30' },
            { 'id':'dotnet6', 'name': '.Net 6', 'endOfLifeDate': '2024-11-12' },
            { 'id':'dotnet7', 'name': '.Net 7', 'endOfLifeDate': '2024-05-14' },
            { 'id':'dotnet3', 'name': '.Net Core 3', 'endOfLifeDate': '2024-01-30' },
            { 'id':'python27', 'name': 'Python 2.7', 'endOfLifeDate': '2021-07-15' },
            { 'id':'python36', 'name': 'Python 3.6', 'endOfLifeDate': '2022-07-18' },
            { 'id':'python37', 'name': 'Python 3.7', 'endOfLifeDate': '2024-01-30' },
            { 'id':'python38', 'name': 'Python 3.8', 'endOfLifeDate': '2024-10-14' },
            { 'id':'python39', 'name': 'Python 3.9', 'endOfLifeDate': '2025-10-05' },
            { 'id':'python310', 'name': 'Python 3.10', 'endOfLifeDate': '2026-10-04' },
            { 'id':'python311', 'name': 'Python 3.11', 'endOfLifeDate': '2027-10-24' },
            { 'id':'python312', 'name': 'Python 3.12', 'endOfLifeDate': '2028-10-02' },
            { 'id':'ruby25', 'name': 'Ruby 2.5', 'endOfLifeDate': '2021-07-30' },
            { 'id':'ruby27', 'name': 'Ruby 2.7', 'endOfLifeDate': '2024-01-30' },
            { 'id':'ruby30', 'name': 'Ruby 3.0', 'endOfLifeDate': '2024-03-31' },
            { 'id':'ruby32', 'name': 'Ruby 3.2', 'endOfLifeDate': '2026-03-31' },
            { 'id':'go121', 'name': 'Go 1.21', 'endOfLifeDate': '2024-05-01' },
            { 'id':'go119', 'name': 'Go 1.19', 'endOfLifeDate': '2024-04-30' },
            { 'id':'go118', 'name': 'Go 1.18', 'endOfLifeDate': '2024-01-30' },
            { 'id':'go116', 'name': 'Go 1.16', 'endOfLifeDate': '2024-01-30' },
            { 'id':'go113', 'name': 'Go 1.13', 'endOfLifeDate': '2024-01-30' },
            { 'id':'java8', 'name': 'Java 8', 'endOfLifeDate': '2024-01-08' },
            { 'id':'java11', 'name': 'Java 11', 'endOfLifeDate': '2024-10-01' },
            { 'id':'java17', 'name': 'Java 17', 'endOfLifeDate': '2027-10-01' },
            { 'id':'php74', 'name': 'PHP 7.4', 'endOfLifeDate': '2024-01-30' },
            { 'id':'php81', 'name': 'PHP 8.1', 'endOfLifeDate': '2024-11-25' },
            { 'id':'php82', 'name': 'PHP 8.2', 'endOfLifeDate': '2025-12-08' },
        ];

        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functionsv2', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            functions.data.forEach(func => {
                if (!func.name) return;

                if (!func.buildConfig || !func.buildConfig.functionTarget) return;

                let runtime = func.labels && func.labels['goog-cloudfunctions-runtime'] ? func.labels['goog-cloudfunctions-runtime'] : null;

                if (!runtime) {
                    helpers.addResult(results, 2,
                        'Cloud Function does not have a runtime configured', region, func.name);
                    return;
                }

                var deprecatedRuntime = deprecatedRuntimes.filter((d) => {
                    return d.id == runtime;
                });

                var version = runtime;
                var runtimeDeprecationDate = (deprecatedRuntime && deprecatedRuntime.length && deprecatedRuntime[0].endOfLifeDate) ? Date.parse(deprecatedRuntime[0].endOfLifeDate) : null;
                let today = new Date();
                today = Date.parse(`${today.getFullYear()}-${today.getMonth()+1}-${today.getDate()}`);
                var difference = runtimeDeprecationDate? Math.round((runtimeDeprecationDate - today)/(1000 * 3600 * 24)): null;
                if (runtimeDeprecationDate && today > runtimeDeprecationDate) { 
                    helpers.addResult(results, 2,
                        'Cloud Function is using runtime: ' + deprecatedRuntime[0].name + ' which was deprecated on: ' + deprecatedRuntime[0].endOfLifeDate,
                        region, func.name);
                } else if (difference && config.function_runtime_fail >= difference) {
                    helpers.addResult(results, 2,
                        'Cloud Function is using runtime: ' + version + ' which is deprecating in ' + Math.abs(difference) + ' days',
                        region, func.name);
                } else {
                    helpers.addResult(results, 0,
                        'Cloud Function is running the current version: ' + version,
                        region, func.name);
                } 
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

