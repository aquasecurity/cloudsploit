const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Automation Account Private Endpoints Configured',
    category: 'Automation',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Azure Automation accounts have private endpoints enabled.',
    more_info: 'Enabling private endpoints for Automation Account enhances security by allowing access exclusively through a private network, minimizing the risk of public network exposure and protecting against external attacks.',
    recommended_action: 'Ensure that private endpoints are configured properly for all Automation Accounts.',
    link: 'https://learn.microsoft.com/en-us/azure/automation/how-to/private-link-security',
    apis: ['automationAccounts:list', 'automationAccounts:get'],
    realtime_triggers: ['microsoftautomation:automationaccounts:write','microsoftautomation:automationaccounts:delete','microsoftautomation:automationcccounts:privateendpointconnectionproxies:write', 'microsoftautomation:automationcccounts:privateendpointconnectionproxies:delete'],

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

                if (describeAcct.data.privateEndpointConnections && describeAcct.data.privateEndpointConnections.length) {
                    helpers.addResult(results, 0, 'Automation Account has private endpoints configured', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'Automation Account does not have private endpoints configured', location, account.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

