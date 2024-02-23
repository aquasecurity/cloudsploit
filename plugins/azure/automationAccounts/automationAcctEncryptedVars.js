const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Encrypted Variables',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensure that Azure Automation account variables have encryption enabled.',
    more_info: 'Azure Automation secures assets such as variables, credentials and certificates using various levels of encryption. Enabling encryption on automation account variables helps enhance the security and privacy of the assets storing sensitive data.',
    recommended_action: 'Delete unencrypted variables in automation account and create new encrypted variables.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/automation-secure-asset-encryption',
    apis: ['automationAccounts:list','accountVariables:listByAutomationAccounts'],
    realtime_triggers: ['microsoftautomation:automationaccounts:runbooks:write','microsoftautomation:automationaccounts:runbooks:delete','microsoftautomation:automationaccounts:variables:write','microsoftautomation:automationaccounts:variables:delete'],
    
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

            for (var account of automationAccounts.data) {
                if (!account.id) continue;

                var accountVariables = helpers.addSource(cache, source,
                    ['accountVariables', 'listByAutomationAccounts', location, account.id]);

                if (!accountVariables || accountVariables.err || !accountVariables.data) {
                    helpers.addResult(results, 3, `Unable to query Automation account variables: ${helpers.addError(accountVariables)}`,
                        location, account.id);
                    continue;
                } else if (!accountVariables.data.length) {
                    helpers.addResult(results, 0, 'No existing Automation accounts variables found', location);
                    continue;
                } else {
                    var unencryptedVariableNames = accountVariables.data.filter(variable => !variable.isEncrypted).map(variable => variable.name);
                    if (unencryptedVariableNames.length) {
                        helpers.addResult(results, 2, `Automation account has following unencrypted variables: ${unencryptedVariableNames.join(',')}`, location, account.id);
                    } else {
                        helpers.addResult(results, 0, 'Automation account has all variables encrypted', location, account.id);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

