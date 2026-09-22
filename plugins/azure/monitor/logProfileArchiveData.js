const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Profile Archive Data',
    category: 'Monitor',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensures the Log Profile is configured to export all activities a storage account',
    more_info: 'Exporting log activity for control plane activity allows for audited access to the Azure account with event data in the case of a security incident.',
    recommended_action: 'Ensure that all activity is logged to a storage account for archiving.' ,
    link: 'https://learn.microsoft.com/en-us/azure/azure-monitor/platform/archive-activity-log',
    apis: ['diagnosticSettingsOperations:list'],
    realtime_triggers: ['microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete'],
    compliance: {
        hipaa: 'HIPAA has clearly defined audit requirements for environments ' +
            'containing sensitive data. Log Profiles are the recommended ' +
            'logging and auditing solution for Azure since it is tightly ' +
            'integrated into most Azure services and APIs.',
        pci: 'Log profiles satisfy the PCI requirement to log all account activity ' +
            'within environments containing cardholder data.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.diagnosticSettingsOperations, (location, rcb) => {
            const diagnosticSettings = helpers.addSource(cache, source,
                ['diagnosticSettingsOperations', 'list', location]);

            if (!diagnosticSettings) return rcb();

            if (diagnosticSettings.err || !diagnosticSettings.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Diagnostic Settings: ' + helpers.addError(diagnosticSettings), location);
                return rcb();
            }

            if (!diagnosticSettings.data.length) {
                helpers.addResult(results, 2, 'No existing Diagnostic Settings found', location);
                return rcb();
            }

            const archivingSetting = diagnosticSettings.data.find(s =>
                s.storageAccountId && s.storageAccountId.length &&
                s.logs && s.logs.some(log => log.enabled));

            if (archivingSetting) {
                helpers.addResult(results, 0,
                    'Diagnostic Setting is archiving Activity Logs to a storage account.', location, archivingSetting.id);
            } else {
                helpers.addResult(results, 2,
                    'No Diagnostic Setting is archiving Activity Logs to a storage account.', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
