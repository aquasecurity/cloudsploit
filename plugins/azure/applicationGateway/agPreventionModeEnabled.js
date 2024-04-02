const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway WAF Prevention Mode Enabled',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure that WAF policy for Microsoft Azure Application gateway is set to Prevention mode.',
    more_info: 'Azure Web Application Firewall (WAF) on Azure Application Gateway provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities.',
    recommended_action: 'Modify application gateway WAF policy and enable prevention mode.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/ag-overview',
    apis: ['wafPolicies:listAll'],
    realtime_triggers: ['microsoftnetwork:applicationgateways:write','microsoftnetwork:applicationgateways:delete','microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:write','microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.wafPolicies, (location, rcb) => {

            var wafPolicies = helpers.addSource(cache, source,
                ['wafPolicies', 'listAll', location]);

            if (!wafPolicies) return rcb();

            if (wafPolicies.err || !wafPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for Application Gateway WAF policies: ' + helpers.addError(wafPolicies), location);
                return rcb();
            }
            if (!wafPolicies.data.length) {
                helpers.addResult(results, 0, 'No existing WAF policies found', location);
                return rcb();
            }

            for (let policy of wafPolicies.data) {
                if (!policy.id) continue;

                if (policy.policySettings && policy.policySettings.mode && policy.policySettings.mode.toLowerCase() === 'prevention') {
                    helpers.addResult(results, 0, 'Prevention mode enabled for application gateway WAF policy', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Prevention mode not enabled for application gateway WAF policy', location, policy.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
