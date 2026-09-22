const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'WAF Policy Bot Protection',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensure that Bot Protection for Azure Application Gateway WAF policy is enabled.',
    more_info: 'Azure Web Application Firewall (WAF) for Application Gateway provides bot rules to block or log requests from known malicious IP addresses identified through the Microsoft Threat Intelligence feed. Enabling the bot manager rule set reduces exposure to automated attacks that scrape, scan and search for application vulnerabilities.',
    recommended_action: 'Modify Application Gateway WAF policy and add the bot manager rule set in managed rules.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/bot-protection',
    apis: ['wafPolicies:listAll'],
    realtime_triggers: ['microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:write', 'microsoftnetwork:applicationgatewaywebapplicationfirewallpolicies:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.wafPolicies, (location, rcb) => {

            var wafPolicies = helpers.addSource(cache, source,
                ['wafPolicies', 'listAll', location]);

            if (!wafPolicies) return rcb();

            if (wafPolicies.err || !wafPolicies.data) {
                helpers.addResult(results, 3, 'Unable to query for WAF policies: ' + helpers.addError(wafPolicies), location);
                return rcb();
            }

            if (!wafPolicies.data.length) {
                helpers.addResult(results, 0, 'No existing WAF policies found', location);
                return rcb();
            }

            for (let policy of wafPolicies.data) {
                if (!policy.id) continue;

                var botRuleSet = policy.managedRules && policy.managedRules.managedRuleSets ?
                    policy.managedRules.managedRuleSets.find(ruleSet => ruleSet.ruleSetType &&
                        ruleSet.ruleSetType.toLowerCase() == 'microsoft_botmanagerruleset') : null;

                if (!botRuleSet) {
                    helpers.addResult(results, 2, 'WAF policy does not have bot protection enabled', location, policy.id);
                    continue;
                }

                var badBotsDisabled = (botRuleSet.ruleGroupOverrides || []).some(override => override.ruleGroupName &&
                    override.ruleGroupName.toLowerCase().indexOf('badbots') > -1 &&
                    override.rules && override.rules.some(rule => rule.state && rule.state.toLowerCase() == 'disabled'));

                if (badBotsDisabled) {
                    helpers.addResult(results, 2, 'WAF policy has malicious bot rules disabled', location, policy.id);
                } else {
                    helpers.addResult(results, 0, 'WAF policy has bot protection enabled', location, policy.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
