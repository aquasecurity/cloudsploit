var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Security Policy Enabled',
    category: 'CLB',
    description: 'Ensure that All Backend Services have an attached Security Policy',
    more_info: 'Security Policies on Backend Services control the traffic on the load balancer. This creates edge security and can deny or allow specified IP addresses.',
    link: 'https://cloud.google.com/armor/docs/security-policy-concepts',
    recommended_action: '1. Enter the Network Security Service. 2. Select Cloud Armor and create a new policy. 3. Attach the newly created policy to the backend.',
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
                    'Unable to query Backend Services: ' + helpers.addError(backendServices), region);
                return rcb();
            }

            if (!backendServices.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers', region);
                return rcb();
            }

            backendServices.data.forEach(backend => {
                if (backend.securityPolicy) {
                    helpers.addResult(results, 0,
                        'The backend service has an attached Security Policy', region, backend.id);
                } else {
                    helpers.addResult(results, 2,
                        'The backend service does not have an attached Security Policy', region, backend.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}