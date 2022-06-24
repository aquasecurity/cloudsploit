var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Security Policy Enabled',
    category: 'CLB',
    domain: 'Availability',
    description: 'Ensures all backend services have an attached security policy',
    more_info: 'Security policies on backend services control the traffic on the load balancer. This creates edge security and can deny or allow specified IP addresses.',
    link: 'https://cloud.google.com/armor/docs/security-policy-concepts',
    recommended_action: 'Ensure all load balancers have an attached Cloud Armor security policy.',
    apis: ['backendServices:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.backendServices, function(region, rcb){
            let backendServices = helpers.addSource(cache, source,
                ['backendServices', 'list', region]);

            if (!backendServices) return rcb();

            if (backendServices.err || !backendServices.data) {
                helpers.addResult(results, 3,
                    'Unable to query backend services', region, null, null, backendServices.err);
                return rcb();
            }

            if (!backendServices.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            let found = false;
            backendServices.data.forEach(backend => {
                if (!backend.name) return;

                found = true;
                let resource = helpers.createResourceName('backendServices', backend.name, project, 'global');

                if (backend.securityPolicy) {
                    helpers.addResult(results, 0,
                        'The backend service has an attached security policy', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'The backend service does not have an attached security policy', region, resource);
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};