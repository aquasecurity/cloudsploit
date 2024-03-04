const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door WAF Latest Default Rule Set',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures that Azure Front Door WAF is using the latest Azure managed default rule set with action set to block.',
    more_info: 'Azure-managed rule sets provide an easy way to deploy protection against a common set of security threats. Azure updates these rules as needed to protect against new attack signatures. ',
    recommended_action: 'Modify the Front Door WAF policy and add latest default rule set.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/afds-overview#waf-policy-and-rules',
    apis: ['afdWafPolicies:listAll'],
    realtime_triggers: ['microsoftnetwork:frontdoorwebapplicationfirewallpolicies:write', 'microsoftnetwork:frontdoorwebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.afdWafPolicies, (location, rcb) => {

            const minimumRuleSetVersion = 2.1;
            //check for minimum allowed default ruleset version
            
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

            var premiumWAF = false;

            for (let policy of afdWafPolicies.data) {
                if (!policy.id || (policy.sku && policy.sku.name != 'Premium_AzureFrontDoor')) continue;

                premiumWAF = true;
                var ruleSet = (policy.managedRules &&
                    policy.managedRules.managedRuleSets &&
                    policy.managedRules.managedRuleSets.find(set => set.ruleSetType && set.ruleSetType.toLowerCase() === 'microsoft_defaultruleset')) || {};

                var ruleSetVersion = ruleSet.ruleSetVersion ? parseFloat(ruleSet.ruleSetVersion) : '';
                var ruleSetAction = ruleSet.ruleSetAction ? ruleSet.ruleSetAction.toLowerCase() : '';

                if (ruleSetVersion >= minimumRuleSetVersion) {
                    if (ruleSetAction == 'block') {
                        helpers.addResult(results, 0, `Front Door WAF policy has latest ${ruleSet.ruleSetType}: ${ruleSet.ruleSetVersion} default rule set configured with ${ruleSetAction} action`, location, policy.id);
                    } else {
                        helpers.addResult(results, 2, `Front Door WAF policy has latest ${ruleSet.ruleSetType}: ${ruleSet.ruleSetVersion} default rule set configured with ${ruleSetAction} action`, location, policy.id);
                    }
                } else {
                    helpers.addResult(results, 2, `Front Door WAF policy have default rule set configured with version less than ${minimumRuleSetVersion}`, location, policy.id);
                }
            }
            
            if (!premiumWAF) {
                helpers.addResult(results, 0, 'No existing Front Door WAF policies found', location);
            }
            rcb();
        }, function () {
            callback(null, results, source);
        });
    }
};