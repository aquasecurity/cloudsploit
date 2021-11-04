var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Ingress All Traffic Disabled',
    category: 'Cloud Functions',
    domain: 'Serverless',
    description: 'Ensure that Cloud Functions are configured to allow only internal traffic or traffic from Cloud Load Balancer.',
    more_info: 'You can secure your google cloud functions by implementing network based access control.',
    link: 'https://cloud.google.com/functions/docs/securing/authenticating',
    recommended_action: 'Ensure that your Google Cloud functions do not allow external traffic from the internet.',
    apis: ['functions:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        async.each(regions.functions, (region, rcb) => {
            var functions = helpers.addSource(cache, source,
                ['functions', 'list', region]);

            if (!functions) return rcb();

            if (functions.err || !functions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Google Cloud Functions: ' + helpers.addError(functions), region, null, null, functions.err);
                return rcb();
            }

            if (!functions.data.length) {
                helpers.addResult(results, 0, 'No Google Cloud functions found', region);
                return rcb();
            }

            functions.data.forEach(func => {
                if (!func.name) return;

                if (func.ingressSettings && func.ingressSettings.toUpperCase() == 'ALLOW_ALL') {
                    helpers.addResult(results, 2, 'Cloud Function is configured to allow all traffic', region, func.name);
                } else {
                    helpers.addResult(results, 0, 'Cloud Function is configured to allow only internal and CLB traffic', region, func.name);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};