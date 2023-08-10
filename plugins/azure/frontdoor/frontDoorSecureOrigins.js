const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Secure Origin',
    category: 'Front Door',
    domain: 'Content Delivery',
    description: 'Ensures that Azure Front Door Standard and Premium profile origins use private link to send traffic to your origin.',
    more_info: 'Configure your origin to only accept traffic through private link making it secure origin. Origins without this security measure risk bypassing Front Door\'s crucial web application firewall, DDoS protection, and other vital security features.',
    recommended_action: 'Ensure that Azure Front Door Standard and Premium profile origins are using private link.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/origin-security?pivots=front-door-standard-premium&tabs=app-service-functions',
    apis: ['profiles:list', 'afdOriginGroups:listByProfile', 'afdOrigin:listByOriginGroups'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.profiles, (location, rcb) => {
            const profiles = helpers.addSource(cache, source,
                ['profiles', 'list', location]);

            if (!profiles) return rcb();

            if (profiles.err || !profiles.data) {
                helpers.addResult(results, 3,
                    'Unable to query Azure Front Door profiles: ' + helpers.addError(profiles), location);
                return rcb();
            }

            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing Azure Front Door profiles found', location);
                return rcb();
            }

            var frontDoorProfile = false;
            profiles.data.forEach(function(profile) {
                if (!profile.id || profile.kind != 'frontdoor') return;

                frontDoorProfile = true;
                var insecureOriginGroupNames = {};
                var originFound = false;

                const afdOriginGroups = helpers.addSource(cache, source,
                    ['afdOriginGroups', 'listByProfile', location, profile.id]);

                if (!afdOriginGroups || afdOriginGroups.err || !afdOriginGroups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Azure Front Door Origin Groups: ' + helpers.addError(afdOriginGroups), location, profile.id);
                } else if (!afdOriginGroups.data.length) {
                    helpers.addResult(results, 0, 'No existing Azure Front Door Origin Groups found', location, profile.id);
                } else {
                    afdOriginGroups.data.forEach(function(originGroup) {
                        const afdOrigin = helpers.addSource(cache, source,
                            ['afdOrigin', 'listByOriginGroups', location, originGroup.id]);

                        if (!afdOrigin || afdOrigin.err || !afdOrigin.data) {
                            helpers.addResult(results, 3,
                                'Unable to query Azure Front Door Origins: ' + helpers.addError(afdOrigin), location, profile.id);
                        } else {
                            originFound = true;
                            insecureOriginGroupNames = afdOrigin.data.filter(origin => {
                                return (origin && (!origin.sharedPrivateLinkResource || !origin.sharedPrivateLinkResource.privateLink));
                            }).map(function(afdOrigin) {
                                return afdOrigin.name;
                            });
                        }
                    });
                    if (originFound) {
                        if (insecureOriginGroupNames.length) {
                            helpers.addResult(results, 2,
                                `Front Door Profile origins are using insecure origins in following origin groups: ${insecureOriginGroupNames.join(', ')}`, location, profile.id);
                        } else {
                            helpers.addResult(results, 0, 
                                'Front Door Profile origins are using secure origins', location, profile.id);
                        }
                    }
                }
            });

            if (!frontDoorProfile) {
                helpers.addResult(results, 0, 'No existing Azure Front Door profiles found', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};