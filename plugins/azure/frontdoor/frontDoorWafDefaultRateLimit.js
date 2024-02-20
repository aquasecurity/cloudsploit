const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door WAF Rate limit',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures that Front Door WAF policy has rate limit custom rule configured.',
    more_info: 'Rate limiting enables you to detect and block abnormally high levels of traffic from any socket IP address. By using Azure Web Application Firewall in Azure Front Door, you can mitigate some types of denial-of-service attacks.',
    recommended_action: 'Modify the Front Door WAF policy and add default rate limit custom rule.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-rate-limit',
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
                var found = policy.customRules && policy.customRules.rules?
                    policy.customRules.rules.find(rule => rule.ruleType && rule.ruleType.toLowerCase() == 'ratelimitrule' && rule.action && rule.action.toLowerCase() == 'block') : false;
                
                if (found) {
                    helpers.addResult(results, 0, 'Front Door WAF policy has rate limit custom rule configured', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Front Door WAF policy does not have rate limit custom rule configured', location, policy.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};