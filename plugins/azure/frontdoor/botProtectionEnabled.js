const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door WAF Bot Protection',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that Bot Protection for Azure Front Door WAF policy is enabled.',
    more_info: 'Azure Web Application Firewall (WAF) for Front Door provides bot rules to protect from bad bots and to block or log requests from known malicious IP addresses.',
    recommended_action: 'Modify Front Door WAF policy and add bot protection rule set in managed rules.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-policy-configure-bot-protection?pivots=portal',
    apis: ['afdWafPolicies:listAll'],
    realtime_triggers: ['microsoftnetwork:frontdoorwebapplicationfirewallpolicies:write', 'microsoftnetwork:frontdoorwebapplicationairewallpolicies:delete'], 

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

                var found = policy.managedRules &&
                    policy.managedRules.managedRuleSets ?
                    policy.managedRules.managedRuleSets.find(ruleset => ruleset.ruleSetType && ruleset.ruleSetType.toLowerCase() == 'microsoft_botmanagerruleset') : false;

                if (found) {
                    helpers.addResult(results, 0, 'Front Door WAF policy has bot protection enabled', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Front Door WAF policy does not have bot protection enabled', location, policy.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
