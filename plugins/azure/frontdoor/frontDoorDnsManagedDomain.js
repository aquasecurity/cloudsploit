var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Domain Managed DNS',
    category: 'Front Door',
    domain: 'Content Delivery',
    description: 'Ensures that Front Door Standard and Premium profile custom domains are configured to use Azure Managed DNS',
    more_info: 'Azure Managed DNS is a hosting service for DNS domains that provides name resolution by using Microsoft Azure infrastructure.',
    recommended_action: 'Ensure that Non-Azure validated domains for Front Door Standard and Premium are using Azure Managed DNS.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/standard-premium/how-to-configure-https-custom-domain?tabs=powershell#azure-front-door-managed-certificates-for-non-azure-pre-validated-domains',
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

            var frontDoorProfile = false;
            profiles.data.forEach(function(profile) {
                if (!profile.id || profile.kind != 'frontdoor') return;
                
                frontDoorProfile = true;
                var failingDomains = {};
                const customDomains = helpers.addSource(cache, source,
                    ['customDomain', 'listByFrontDoorProfiles', location, profile.id]);
                if (!customDomains || customDomains.err || !customDomains.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Front Door custom domains: ' + helpers.addError(customDomains), location, profile.id);
                } else if (!customDomains.data.length) {
                    helpers.addResult(results, 0, 'No existing Front Door custom domains found', location, profile.id);
                } else {
                    failingDomains = customDomains.data.filter(customDomain => {
                        return (!customDomain.azureDnsZone);
                    }).map(function(customDomain) {
                        return customDomain.name; 
                    });

                    if (failingDomains.length){
                        helpers.addResult(results, 2,
                            `Front Door Profile domains are not using Azure managed DNS ${failingDomains.join(', ')}`, location, profile.id);
                    } else {
                        helpers.addResult(results, 0,
                            'Front Door Profile domains are using Azure managed DNS', location, profile.id);
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