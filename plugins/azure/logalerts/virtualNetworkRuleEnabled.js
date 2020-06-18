const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Virtual Network Alerts Monitor',
    category: 'Log Alerts',
    description: 'Ensures Activity Log Alerts for the create or update and delete Virtual Networks events are enabled',
    more_info: 'Monitoring for create or update and delete Virtual Networks events gives insight into event changes and may reduce the time it takes to detect suspicious activity.',
    recommended_action: 'Add a new log alert to the Alerts service that monitors for Virtual Networks create or update and delete events.',
    link: 'https://docs.microsoft.com/en-us/azure/virtual-network/security-overview',
    apis: ['activityLogAlerts:listBySubscriptionId'],
    compliance: {
        hipaa: 'HIPAA requires the auditing of changes to access controls for network ' +
                'resources.',
        pci: 'PCI requires the use of firewalls to protect cardholder data. Configuring ' +
                'a monitor for changes to Virtual Networks ensures the integrity of those ' +
                'firewalls.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.activityLogAlerts, function(location, rcb) {

            var conditionResource = 'microsoft.network/virtualnetworks';

            var text = 'Virtual Networks';

            var activityLogAlerts = helpers.addSource(cache, source,
                ['activityLogAlerts', 'listBySubscriptionId', location]);

            helpers.checkLogAlerts(activityLogAlerts, conditionResource, text, results, location);
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
