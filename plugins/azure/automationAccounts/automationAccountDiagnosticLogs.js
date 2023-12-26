const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Diagnostic Logs',
    category: 'Automation',
    domain: 'Management and Governance',
    description: 'Ensures that diagnostic logging is enabled for Azure Automation account.',
    more_info: 'Azure Automation can send runbook job status and job streams to get insights, alert emails and correlate jobs accross automation accounts. It also allows you to get the audit logs related to Automation accounts, runbooks, and other asset create, modify and delete operations.',
    recommended_action: 'Enable diagnostic logging for all Automation accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics#azure-automation-diagnostic-settings',
    apis: ['automationAccounts:list','diagnosticSettings:listByAutomationAccounts'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.automationAccounts, (location, rcb) => {

            const automationAccounts = helpers.addSource(cache, source,
                ['automationAccounts', 'list', location]);

            if (!automationAccounts) return rcb();

            if (automationAccounts.err || !automationAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query Automation accounts: ' + helpers.addError(automationAccounts), location);
                return rcb();
            }

            if (!automationAccounts.data.length) {
                helpers.addResult(results, 0, 'No existing Automation accounts found', location);
                return rcb();
            }

            for (let account of automationAccounts.data) {
                if (!account.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByAutomationAccounts', location, account.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query Automation account diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, account.id);
                    continue;
                }

                var missingLogs = ['JobLogs', 'JobStreams', 'DscNodeStatus', 'AuditEvent'];
                diagnosticSettings.data.forEach(settings => {
                    const logs = settings.logs;
                    missingLogs = missingLogs.filter(requiredCategory =>
                        !logs.some(log => (log.category === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                    );
                });

                if (missingLogs.length) {
                    helpers.addResult(results, 2, `Automation account does not have diagnostic logs enabled. Missings logs: ${missingLogs}`, location, account.id);
                } else {
                    helpers.addResult(results, 0, 'Automation account has diagnostic logs enabled', location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

