var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CLB CDN Enabled',
    category: 'CLB',
    description: 'Ensures that Cloud CDN is enabled on all load balancers',
    more_info: 'Cloud CDN increases speed and reliability as well as lowers server costs. Enabling CDN on load balancers creates a highly available system and is part of GCP best practices.',
    link: 'https://cloud.google.com/cdn/docs/quickstart',
    recommended_action: 'Enable Cloud CDN on all load balancers from the network services console.',
    apis: ['backendServices:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.backendServices, function(region, rcb){
            let backendServices = helpers.addSource(cache, source,
                ['backendServices', 'list', region]);

            if (!backendServices) return rcb();

            if (backendServices.err || !backendServices.data) {
                helpers.addResult(results, 3,
                    'Unable to query backend services: ' + helpers.addError(backendServices), region);
                return rcb();
            }

            if (!backendServices.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            backendServices.data.forEach(backend => {
                if (backend.enableCDN) {
                    helpers.addResult(results, 0,
                        'CDN is enabled on the backend service', region, backend.id);
                } else {
                    helpers.addResult(results, 2,
                        'CDN is disabled on the backend service', region, backend.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}