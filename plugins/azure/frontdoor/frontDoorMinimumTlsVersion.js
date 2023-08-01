var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Minimum TLS Version',
    category: 'Front Door',
    domain: 'CDN Profiles',
    description: 'Ensures that Azure Front Door Standard and Premium profile custom domains have minimum TLS version of 1.2',
    more_info: 'By setting the minimum TLS version to 1.2, you significantly improve the security of your custom domains. All Azure Front Door profiles created after September 2019 use TLS 1.2 as the default minimum',
    recommended_action: 'Ensures that Azure Front Door Standard and Premium should be running minimum TLS version of 1.2',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/end-to-end-tls?pivots=front-door-standard-premium#supported-tls-versions',
    apis: ['profiles:list', 'customDomain:listByFrontDoorProfiles'],
    
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

            profiles.data.forEach(function(profile){
                if (!profile.id || profile.kind!= 'frontdoor') return;

                const customDomains = helpers.addSource(cache, source,
                    ['customDomain', 'listByFrontDoorProfiles', location, profile.id]);
                if (!customDomains || customDomains.err || !customDomains.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Front Door custom domains: ' + helpers.addError(customDomains), location, profile.id);
                } else if (!customDomains.data.length) {
                    helpers.addResult(results, 0, 'No existing Front Door custom domains found', location, profile.id);
                } else {
                    customDomains.data.forEach(function(customDomain) {
                        if (customDomain.tlsSettings && 
                            customDomain.tlsSettings.minimumTlsVersion && 
                            customDomain.tlsSettings.minimumTlsVersion.toUpperCase() == 'TLS12' ) {
                            helpers.addResult(results, 0,
                                'AFD profile custom domain is using TLS version 1.2', location, customDomain.id);
                        } else {
                            helpers.addResult(results, 2,
                                'AFD profile custom domain is not using TLS version 1.2', location, customDomain.id);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};