const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Waf Enabled',
    category: 'Front Door',
    domain: 'Content Delivery',
    description: 'Ensure that WAF is enabled for Azure Front Door premium profile.',
    more_info: 'WAF actively inspects incoming requests to the front door and blocks requests that are determined to be malicious based on a set of rules.',
    recommended_action: 'Ensure that Azure Front Door premium profile has WAF policy attached in security policies section.',
    link: 'https://learn.microsoft.com/en-us/azure/web-application-firewall/afds/waf-front-door-policy-settings',
    apis: ['profiles:list', 'afdSecurityPolicies:listByProfile',],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.profiles, (location, rcb) => {

            var profiles = helpers.addSource(cache, source,
                ['profiles', 'list', location]);

            if (!profiles) return rcb();

            if (profiles.err || !profiles.data) {
                helpers.addResult(results, 3, 'Unable to query Front Door profiles: ' + helpers.addError(profiles), location);
                return rcb();
            }
            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing Front Door profiles found', location);
                return rcb();
            }

            var frontDoorPremium = false;

            profiles.data.forEach(function(profile) {
                if (!profile.id || !profile.sku || profile.sku.name.toLowerCase() != 'premium_azurefrontdoor') return;
                
                frontDoorPremium = true;
                const afdSecurityPolicies = helpers.addSource(cache, source,
                    ['afdSecurityPolicies', 'listByProfile', location, profile.id]);
                if (!afdSecurityPolicies || afdSecurityPolicies.err || !afdSecurityPolicies.data) {
                    helpers.addResult(results, 3, 'Unable to query Front Door security policies : ' + helpers.addError(afdSecurityPolicies), location, profile.id);
                } else {
                    if (!afdSecurityPolicies.data.length) {
                        helpers.addResult(results, 2, 'Front Door profile does not have WAF enabled', location, profile.id);
                    } else {
                        helpers.addResult(results, 0, 'Front Door profile has WAF enabled', location, profile.id);
                    }
                }
            });
            
            if (!frontDoorPremium) {
                helpers.addResult(results, 0, 'No existing Front Door profiles found', location);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
