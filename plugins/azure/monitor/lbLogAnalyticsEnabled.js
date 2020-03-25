const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Load Balancer Log Analytics Enabled',
    category: 'Monitor',
    description: 'Ensures Load Balancers Log Analytics logs are being properly delivered to Azure Monitor',
    more_info: 'Enabling Send to Log Analytics ensures that all Load Balancer logs are being properly monitored and managed.',
    recommended_action: 'Send all diagnostic logs for Load Balancers from the Azure Monitor service to Log Analytics.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/platform/collect-activity-logs',
    apis: ['loadBalancers:listAll', 'diagnosticSettingsOperations:lb:list'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit log record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations.lb, (location, rcb) => {

            const diagnosticSettingsResources = helpers.addSource(cache, source, 
                ['diagnosticSettingsOperations', 'lb', 'list', location]);

            if (!diagnosticSettingsResources) return rcb();

            if (diagnosticSettingsResources.err || !diagnosticSettingsResources.data ) {
                helpers.addResult(results, 3,
                    'Unable to query Diagnostic Settings: ' + helpers.addError(diagnosticSettingsResources),location);
                return rcb();
            }

            if (!diagnosticSettingsResources.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers found', location);
                return rcb();
            }

            diagnosticSettingsResources.data.forEach(loadBalancerSettings => {
                var isWorkspace = loadBalancerSettings.value.filter((d) => {
                    return d.hasOwnProperty('workspaceId') == true;
                });

                if (!loadBalancerSettings.value.length) {
                    helpers.addResult(results, 2,
                        'Diagnostic Settings are not configured for the Load Balancer', location, loadBalancerSettings.id);
                } else {
                    if (isWorkspace.length) {
                        helpers.addResult(results, 0,
                        'Send to Log Analytics is configured for the Load Balancer', location, loadBalancerSettings.id);
                    } else {
                        helpers.addResult(results, 2,
                        'Send to Log Analytics is not configured for the Load Balancer', location, loadBalancerSettings.id);
                    }
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
