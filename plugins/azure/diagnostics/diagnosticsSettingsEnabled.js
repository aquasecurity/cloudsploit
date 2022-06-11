const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Diagnostics Settings Enabled',
    category: 'Monitor',
    domain: 'Management and Governance',
    description: 'Ensures that Diagnostics Settings for exporting logs is enabled.',
    more_info: 'Enable Diagnostic settings for exporting activity logs. Diagnostic setting are available for each individual resources within a subscription. Settings should be configured for all appropriate resources for your environment.',
    recommended_action: 'Ensure that a Diagnostic status is enabled on all appropriate resources.',
    link: 'https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-overview-activity-logs#export-the-activity-log-with-a-log-profile',
    apis: ['diagnosticSettingsOperations:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations, (location, rcb) => {
            const diagnosticSettings = helpers.addSource(cache, source,
                ['diagnosticSettingsOperations', 'list', location]);

            if (!diagnosticSettings) return rcb();

            if (diagnosticSettings.err || !diagnosticSettings.data) {
                helpers.addResult(results, 3, 'Unable to query for Diagnostic Settings : ' + helpers.addError(diagnosticSettings), location);
                return rcb();
            }

            if (!diagnosticSettings.data.length) {
                helpers.addResult(results, 2, 'No existing Diagnostic Settings found', location);
                return rcb();
            }

            diagnosticSettings.data.forEach(settings => {
                if (settings.logs && settings.logs.length) {
                    let disabledLog = settings.logs.find(log => !log.enabled);

                    if (disabledLog) {
                        helpers.addResult(results, 2, 'Diagnostic Setting is not enabled for exporting logs on all resources', location, settings.id);
                    } else if (settings.storageAccountId && settings.storageAccountId.length) {
                        helpers.addResult(results, 0, 'Diagnostic Setting is enabled for exporting logs for all resources', location, settings.id);
                    } else {
                        helpers.addResult(results, 2, 'Diagnostic Setting does not have a Storage Account configured for Azure Monitor Logs', location, settings.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
