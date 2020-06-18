const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Load Balancer Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Load Balancers Log Analytics logs are being properly delivered to Azure Monitor',
    more_info: 'Enabling Send to Log Analytics ensures that all Load Balancer logs are being properly monitored and managed.',
    recommended_action: 'Send all diagnostic logs for Load Balancers from the Azure Monitor service to Log Analytics.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['loadBalancers:listAll', 'diagnosticSettings:listByLoadBalancer'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit log record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.loadBalancers, (location, rcb) => {
            const loadBalancers = helpers.addSource(cache, source,
                ['loadBalancers', 'listAll', location]);

            if (!loadBalancers) return rcb();

            if (loadBalancers.err || !loadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Load Balancers: ' + helpers.addError(loadBalancers), location);
                return rcb();
            }

            if (!loadBalancers.data.length) {
                helpers.addResult(results, 0, 'No existing Load Balancers found', location);
                return rcb();
            }

            loadBalancers.data.forEach(function(loadBalancer) {
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByLoadBalancer', location, loadBalancer.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, loadBalancer.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing diagnostics settings', location, loadBalancer.id);
                } else {
                    var found = false;
                    diagnosticSettings.data.forEach(function(ds) {
                        if (ds.logs && ds.logs.length) found = true;
                    });

                    if (found) {
                        helpers.addResult(results, 0, 'Log analytics is enabled for load balancer', location, loadBalancer.id);
                    } else {
                        helpers.addResult(results, 2, 'Log analytics is not enabled for load balancer', location, loadBalancer.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
