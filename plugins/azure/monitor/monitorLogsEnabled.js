const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Monitor Logs Enabled',
    category: 'Monitor',
    domain: 'Management and Governance',
    description: 'Ensure that Azure Monitor Logs are enabled for all logging categories and being archived in a Storage Account.',
    more_info: 'Azure Monitor Logs is a feature of Azure Monitor that collects and organizes log and performance data from monitored resources and helps in identifying issues in resources performance.',
    recommended_action: 'Enabled Azure Monitor Logs for all logging categories and archive in a Storage Account',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-platform-logs',
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
                        helpers.addResult(results, 2, 'Diagnostic Setting does not have Azure Monitor Logs enabled for all the logging categories', location, settings.id);
                    } else if (settings.storageAccountId && settings.storageAccountId.length) {
                        helpers.addResult(results, 0, 'Diagnostic Setting has Azure Monitor Logs enabled for all the logging categories and Storage Account configured', location, settings.id);
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
