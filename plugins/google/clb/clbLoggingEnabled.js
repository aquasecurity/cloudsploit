var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CLB Logging Enabled',
    category: 'CLB',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensures that logging is enabled for all HTTP(s) load balancers',
    more_info: 'Enabling logging on a HTTP(s) Load Balancer will show all network traffic and its destination which can be used to assess its performance, usage, configuration and in troubleshooting any problems.',
    link: 'https://cloud.google.com/load-balancing/docs/https/https-logging-monitoring',
    recommended_action: 'Enable logging for all HTTP(s) load balancers from the network services console.',
    apis: ['backendServices:list'],
    realtime_triggers: ['compute.backendServices.patch','compute.backendServices.insert','compute.backendServices.delete'],

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
                if (backend.logConfig && backend.logConfig.enable) {
                    helpers.addResult(results, 0,
                        'Logging is enabled for the backend service', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Logging is disabled for the backend service', region, resource);
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No HTTP(s) load balancers found', region);
                return rcb();
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};