const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Expired Webhooks',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Azure Automation webhooks are deleted after they have expired.',
    more_info: 'Expired webhooks increase the risk of unauthorized access, compromising security. Setting a validity period aligns with corporate policies, minimizing the potential for misuse and enhancing overall security.',
    recommended_action: 'Delete the expired webhook and re-create it.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/automation-webhooks',
    apis: ['automationAccounts:list', 'webhooks:listByAutomationAccounts'],
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:webhooks:write', 'microsoftautomation:automationaccounts:webhooks:delete'],

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

                var webhooks = helpers.addSource(cache, source,
                    ['webhooks', 'listByAutomationAccounts', location, account.id]);

                if (!webhooks || webhooks.err || !webhooks.data ) {
                    helpers.addResult(results, 3, 'Unable to query for Automation account webhooks: ' + helpers.addError(webhooks), location);
                    continue;
                } 
                
                if (!webhooks.data.length) {
                    helpers.addResult(results, 3, 'No existing webhooks for Automation account found', location, account.id);
                    continue;
                }
                var today = new Date();
                webhooks.data.forEach(function(webhook) { 
                  var expiryTime = new Date(Date.parse(webhook.expiryTime));

                    if (expiryTime < today) {
                        helpers.addResult(results, 2, 'Automation account webhook has expired', location, webhook.id);
                    } else {
                        helpers.addResult(results, 0, 'Automation account webhook is valid', location, webhook.id);
                    }
                });
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

