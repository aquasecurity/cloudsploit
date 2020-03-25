var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CLB No Instances',
    category: 'CLB',
    description: 'Detects CLBs that have no backend instances attached',
    more_info: 'GCP does not allow for Load Balancers to be configured without backend instances attached.',
    link: 'https://cloud.google.com/load-balancing/docs/load-balancing-overview',
    recommended_action: 'This security misconfiguration is covered by GCP. No action is necessary.',
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

            helpers.addResult(results, 0, 'All load balancers have backend services.', region);

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}