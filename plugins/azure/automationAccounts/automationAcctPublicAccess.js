const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Public Access Disabled',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'High',
    description: 'Ensure that Azure Automation accounts have have public access disabled.',
    more_info: 'Disabling public network access ensures that network traffic between the machines on the VNet and the Automation account traverses over the a private link, eliminating exposure from the public internet.',
    recommended_action: 'Modify automation account and disable public access.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/how-to/private-link-security',
    apis: ['automationAccounts:list', 'automationAccounts:get'],
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:delete'],

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

                var describeAcct = helpers.addSource(cache, source,
                    ['automationAccounts', 'get', location, account.id]);

                if (!describeAcct || describeAcct.err || !describeAcct.data ) {
                    helpers.addResult(results, 3, 'Unable to query for Automation account: ' + helpers.addError(describeAcct), location);
                    continue;
                }

                if (Object.prototype.hasOwnProperty.call(describeAcct.data, 'publicNetworkAccess')) {
                    if (describeAcct.data.publicNetworkAccess) {
                        helpers.addResult(results, 2, 'Automation account does not have public network access disabled', location, account.id);
                    } else {
                        helpers.addResult(results, 0, 'Automation account has public network access disabled', location, account.id);
                    }
                } else {
                    helpers.addResult(results, 2, 'Automation account does not have public network access disabled', location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

