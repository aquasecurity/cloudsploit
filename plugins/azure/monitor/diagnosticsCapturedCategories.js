const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Diagnostics Captured Categories',
    category: 'Monitor',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Diagnostics Settings is configured to log activities for all appropriate categories.',
    more_info: 'Monitor diagnostic setting in Azure controls how the diagnostic logs are exported. When a diagnostic setting is created, ' +
        'by default no log categories are selected. Capturing the appropriate log categories (Administrative, Security, Alert, and Policy) ' +
        'for the activities performed within your Azure subscriptions provides proper alerting.',
    recommended_action: 'Ensure the categories Administrative, Alert, Policy, and Security are set to Enabled for all diagnostic settings.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/samples/resource-manager-diagnostic-settings',
    apis: ['diagnosticSettingsOperations:list'],
    realtime_triggers: ['microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        const appropriateCategories = ['Administrative', 'Alert', 'Policy', 'Security'];

        async.each(locations.diagnosticSettingsOperations, (location, rcb) => {
            const diagnosticSettings = helpers.addSource(cache, source,
                ['diagnosticSettingsOperations', 'list', location]);

            if (!diagnosticSettings) return rcb();

            if (diagnosticSettings.err || !diagnosticSettings.data) {
                helpers.addResult(results, 3, 'Unable to query for Diagnostic Settings : ' + helpers.addError(diagnosticSettings), location);
                return rcb();
            }

            if (!diagnosticSettings.data.length) {
                helpers.addResult(results, 0, 'No existing Diagnostic Settings found', location);
                return rcb();
            }

            diagnosticSettings.data.forEach(settings => { 
                let enabledCategories = [];

                if (settings.logs && settings.logs.length) {
                    settings.logs.forEach(log => {
                        if (log.enabled && appropriateCategories.indexOf(log.category) > -1) {
                            if (enabledCategories.indexOf(log.category) === -1) {
                                enabledCategories.push(log.category);
                            }
                        }
                    });

                    if (appropriateCategories.length == enabledCategories.length) {
                        helpers.addResult(results, 0, 'Diagnostic Setting is configured to log required categories', location, settings.id);
                    } else {
                        helpers.addResult(results, 2, 'Diagnostic Setting is not configured to log required categories', location, settings.id);
                    }
                } else {
                    helpers.addResult(results, 2, 'Diagnostic Setting does not have any logs configured', location, settings.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
