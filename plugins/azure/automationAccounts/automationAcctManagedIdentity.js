const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Managed Identity',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Azure Automation accounts have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify automation account and enable managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/quickstarts/enable-managed-identity',
    apis: ['automationAccounts:list'],
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:delete','microsoftautomation:automationaccounts:runbooks:write','microsoftautomation:automationaccounts:runbooks:delete'],

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

                if (account.identity && account.identity.type) {
                    helpers.addResult(results, 0, 'Automation account has managed identity enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Automation account does not have managed identity enabled', location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

