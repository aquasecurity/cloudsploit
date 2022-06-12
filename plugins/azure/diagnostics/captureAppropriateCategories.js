const async = require('async');
const _ = require('underscore');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Capture Appropriate Categories Logs',
    category: 'Monitor',
    domain: 'Management and Governance',
    description: 'Ensures that Diagnostics Settings is capturing logs for all appropriate categories.',
    more_info: 'A diagnostic setting controls how the diagnostic log is exported. Capturing the diagnostic setting categories for appropriate control/management plane activities allows proper alerting.',
    recommended_action: 'Ensure that Diagnostic settings is enabled on all appropriate categories.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-monitor/samples/resource-manager-diagnostic-settings',
    apis: ['diagnosticSettingsOperations:list'],

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
                helpers.addResult(results, 2, 'No existing Diagnostic Settings found', location);
                return rcb();
            }

            let enabledCategories = [];
            diagnosticSettings.data.forEach(settings => {
                if (settings.logs && settings.logs.length) {
                    settings.logs.forEach(log => {
                        if (log.enabled && appropriateCategories.indexOf(log.category) > -1) {
                            if (enabledCategories.indexOf(log.category) === -1) {
                                enabledCategories.push(log.category);
                            }
                        }
                    });

                    if (_.difference(appropriateCategories, enabledCategories).length === 0) {
                        helpers.addResult(results, 0, 'Logs for all appropriate categories are enabled for Diagnostic Settings', location);
                    } else {
                        helpers.addResult(results, 2, 'Logs for all appropriate categories are not enabled for Diagnostic Settings', location);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
