const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Request Body Inspection',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures that request body inspection is enabled for Azure Front Door WAF policy.',
    more_info: 'Web Application Firewalls associated to Azure Front Doors that have request body inspection enabled allow to inspect properties within the HTTP body that may not be evaluated in the HTTP headers, cookies, or URI.',
    recommended_action: 'Modify Front Door WAF policy and enable request body inspection in policy settings.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits#request-body-inspection',
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

                if (policy.policySettings && 
                    policy.policySettings.requestBodyCheck && 
                    policy.policySettings.requestBodyCheck.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0, 'Front Door WAF policy has request body inspection enabled', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Front Door WAF policy does not have request body inspection enabled', location, policy.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};