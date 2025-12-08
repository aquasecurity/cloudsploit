var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Ingress All Traffic Disabled V2',
    category: 'Cloud Functions',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensure that Cloud Functions V2 are configured to allow only internal traffic or traffic from Cloud Load Balancer.',
    more_info: 'You can secure your Google Cloud Functions V2 by implementing network-based access control.',
    link: 'https://cloud.google.com/functions/docs/securing/authenticating',
    recommended_action: 'Ensure that your Google Cloud Functions V2 do not allow external traffic from the internet.',
    apis: ['functionsv2:list'],
    realtime_triggers: ['functions.CloudFunctionsService.UpdateFunction', 'functions.CloudFunctionsService.CreateFunction', 'functions.CloudFunctionsService.DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
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

                let ingressSettings = func.ingress || null;

                if (ingressSettings && ingressSettings.toUpperCase() == 'INGRESS_TRAFFIC_ALL') {
                    helpers.addResult(results, 2,
                        'Cloud Function is configured to allow all traffic', region, func.name);
                } else if (ingressSettings) {
                    helpers.addResult(results, 0,
                        'Cloud Function is configured to allow only internal and CLB traffic', region, func.name);
                } else {
                    helpers.addResult(results, 2,
                        'Cloud Function does not have ingress settings configured', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

