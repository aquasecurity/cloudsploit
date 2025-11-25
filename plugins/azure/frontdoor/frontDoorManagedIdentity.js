const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Front Door Managed Identity Enabled',
    category: 'Front Door',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Azure Front Door standard and premium profiles have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Entra ID tokens.',
    recommended_action: 'Modify the Front Door standard and premium profile and add managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/frontdoor/managed-identity',
    apis: ['profiles:list'],
    realtime_triggers: ['microsoftcdn:profiles:write', 'microsoftcdn:profiles:delete'],
  
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
                    'Unable to query Front Door profiles: ' + helpers.addError(profiles), location);
                return rcb();
            }

            if (!profiles.data.length) {
                helpers.addResult(results, 0, 'No existing Azure Front Door profiles found', location);
                return rcb();
            }

            var frontDoorProfile = false;
            profiles.data.forEach(function(profile) {
                if (!profile.id || profile.kind!='frontdoor') return;
                
                frontDoorProfile = true;
                if (profile.identity && profile.identity.type && 
                    (profile.identity.type.toLowerCase() === 'systemassigned' || profile.identity.type.toLowerCase() === 'userassigned')) {
                    helpers.addResult(results, 0,
                        'Front Door profile has managed identity enabled', location, profile.id);
                } else {
                    helpers.addResult(results, 2,
                        'Front Door profile does not have managed identity enabled', location, profile.id);
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