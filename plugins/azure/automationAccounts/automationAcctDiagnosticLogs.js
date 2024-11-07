const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Diagnostic Logs',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that diagnostic logging is enabled for Azure Automation account.',
    more_info: 'Azure Automation can send runbook job status and job streams to get insights, alert emails and correlate jobs across automation accounts. It also allows you to get the audit logs related to Automation accounts, runbooks, and other asset create, modify and delete operations.',
    recommended_action: 'Enable diagnostic logging for all Automation accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/automation-manage-send-joblogs-log-analytics#azure-automation-diagnostic-settings',
    apis: ['automationAccounts:list', 'diagnosticSettings:listByAutomationAccounts'],
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],
    settings: {
        diagnostic_logs: {
            name: 'Diagnostic Logs Enabled',
            description: 'Comma separated list of diagnostic logs that should be enabled at minimum i.e. JobLogs, JobStreams etc. If you have enabled allLogs, then resource produces pass result. If you only want to check if logging is enabled or not, irrespecitve of log type, then add * in setting.',
            regex: '^.*$',
            default: 'JobLogs, JobStreams, DscNodeStatus, AuditEvent'
        },
    },
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        
        var config = {
            diagnostic_logs: settings.diagnostic_logs || this.settings.diagnostic_logs.default,
        };
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

                var found = true;
                var missingLogs = [];
                if (config.diagnostic_logs == '*') {
                    found = diagnosticSettings.data.some(ds => ds.logs && ds.logs.length);
                } else {
                    config.diagnostic_logs = config.diagnostic_logs.replace(/\s/g, '');
                    missingLogs = config.diagnostic_logs.toLowerCase().split(',');
                    diagnosticSettings.data.forEach(settings => {
                        const logs = settings.logs;
                        missingLogs = missingLogs.filter(requiredCategory =>
                            !logs.some(log => (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                        );
                    });

                }

                if (!missingLogs.length && found) {
                    helpers.addResult(results, 0, 'Automation account has diagnostic logs enabled', location, account.id);

                } else {
                    helpers.addResult(results, 2, `Automation account does not have diagnostic logs enabled ${missingLogs.length ? `for following: ${missingLogs}` : ''}`, location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
