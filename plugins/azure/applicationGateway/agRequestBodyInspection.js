const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway Request Body Inspection',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that request body inspection is enabled for Application Gateway WAF policy.',
    more_info: 'Application Gateway WAF policy with disabled request body inspection doesn\'t evaluate the contents of an HTTP message\'s body. Enabling it allows us to inspect properties that may not be evaluated in the HTTP headers, cookies, or URI.',
    recommended_action: 'Modify application gateway WAF policy and enable request body inspection in policy settings.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/ag/application-gateway-waf-request-size-limits#request-body-inspection',
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

                if (policy.policySettings && policy.policySettings.requestBodyCheck) {
                    helpers.addResult(results, 0, 'Application gateway WAF policy has request body inspection enabled', location, policy.id);
                } else {
                    helpers.addResult(results, 2, 'Application gateway WAF policy does not have request body inspection enabled', location, policy.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
