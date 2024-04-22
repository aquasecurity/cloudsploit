const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door WAF Detection Mode',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that WAF policy for Azure Front Door is set to Detection mode.',
    more_info: 'Web Application Firewall (WAF) on Front Door provides centralized protection of your web applications from common exploits and vulnerabilities. Web applications are increasingly targeted by malicious attacks that exploit commonly known vulnerabilities. It monitors and logs the request and its matched WAF rule to WAF logs.',
    recommended_action: 'Modify Front Door WAF policy and enable prevention mode.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview',
    apis: ['afdWafPolicies:listAll'],
    realtime_triggers: ['microsoftnetwork:frontdoorwebapplicationfirewallpolicies:write', 'microsoftnetwork:frontdoorwebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.afdWafPolicies, (location, rcb) => {
            var afdWafPolicies = helpers.addSource(cache, source,
                ['afdWafPolicies', 'listAll', location]);

            if (!afdWafPolicies) return rcb();

            if (afdWafPolicies.err || !afdWafPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for Front Door WAF policies: ' + helpers.addError(afdWafPolicies), location);
                return rcb();
            }
            if (!afdWafPolicies.data.length) {
                helpers.addResult(results, 0, 'No existing Front Door WAF policies found', location);
                return rcb();
            }

            for (let policy of afdWafPolicies.data) {
                if (!policy.id) continue;

                if (policy.policySettings && policy.policySettings.mode && policy.policySettings.mode.toLowerCase() == 'detection') {
                    helpers.addResult(results, 0, 'Detection mode enabled for Front Door WAF policy', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Detection mode not enabled for Front Door WAF policy', location, policy.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
