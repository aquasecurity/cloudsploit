var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Ingress All Traffic Disabled',
    category: 'Cloud Functions',
    description: 'Ensure that Cloud Functions are configured to allow only internal traffic or traffic from Cloud Load Balancing.',
    more_info: 'You can secure your google cloud functions by implementing network based access control.',
    link: 'https://cloud.google.com/functions/docs/securing/authenticating',
    recommended_action: 'Ensure that your Google Cloud functions do not allow external traffic from the internet.',
    apis: ['functions:list', 'projects:get'],

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

            functions.data.forEach(funct => {

                if (funct.ingressSettings && (funct.ingressSettings == 'ALLOW_INTERNAL_AND_GCLB' || funct.ingressSettings == 'ALLOW_INTERNAL_ONLY')) {
                    helpers.addResult(results, 0, 'Cloud Function is configured to allow only internal and GCLB traffic', region, funct.name);
                } else {
                    helpers.addResult(results, 2, 'Cloud Function is not configured to allow only internal and GCLB traffic', region, funct.name);
                }

            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};