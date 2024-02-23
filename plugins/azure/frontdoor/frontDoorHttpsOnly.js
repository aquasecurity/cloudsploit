const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door HTTPS only',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures HTTPS Only is enabled for Front Door classic profile, redirecting all HTTP traffic to HTTPS.',
    more_info: 'By using the HTTPS only protocol, you ensure that your sensitive data is delivered securely via TLS/SSL encryption.',
    recommended_action: 'Modify the Front Door classic profile and add HTTP to HTTPS redirect rule under the frontend hosts section.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/front-door-how-to-redirect-https',
    apis: ['classicFrontDoors:list'],
    realtime_triggers: ['microsoftnetwork:frontdoors:write', 'microsoftnetwork:frontdoors:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.classicFrontDoors, (location, rcb) => {
            const classicFrontDoors = 
            helpers.addSource(cache, source,
                ['classicFrontDoors', 'list', location]);

            if (!classicFrontDoors) return rcb();

            if (classicFrontDoors.err || !classicFrontDoors.data) {
                helpers.addResult(results, 3,
                    'Unable to query Front Door profiles: ' + helpers.addError(classicFrontDoors), location);
                return rcb();
            }

            if (!classicFrontDoors.data.length) {
                helpers.addResult(results, 0, 'No existing Front Door profiles found', location);
                return rcb();
            }

            classicFrontDoors.data.forEach(frontDoor => {
                if (!frontDoor.id || !frontDoor.routingRules) return;

                var ruleFound = false;
                for (var rule of frontDoor.routingRules) {
                    var ruleProperties = rule.properties? rule.properties : {};
                    if (ruleProperties.acceptedProtocols && ruleProperties.acceptedProtocols[0].toLowerCase() =='http') {
                        if (ruleProperties.routeConfiguration && 
                            ruleProperties.routeConfiguration.redirectType && 
                            ruleProperties.routeConfiguration.redirectProtocol && 
                            ruleProperties.routeConfiguration.redirectType.toLowerCase() == 'moved' &&
                            ruleProperties.routeConfiguration.redirectProtocol.toLowerCase() == 'httpsonly') {
                            ruleFound = true;
                            break;
                        }
                    }
                }

                if (ruleFound) {
                    helpers.addResult(results, 0, 'Front Door profile is configured to use HTTPS only', location, frontDoor.id);
                } else {
                    helpers.addResult(results, 2, 'Front Door profile is not configured to use HTTPS only', location, frontDoor.id);
                }
               
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};