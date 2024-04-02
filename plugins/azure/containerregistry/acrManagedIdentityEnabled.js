var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Managed Identity Enabled',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Azure container registries have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify container registry and enable managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/container-registry-authentication-managed-identity?tabs=azure-cli',
    apis: ['registries:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.registries, function(location, rcb) {
            var registries = helpers.addSource(cache, source,
                ['registries', 'list', location]);

            if (!registries) return rcb();

            if (registries.err || !registries.data) {
                helpers.addResult(results, 3,
                    'Unable to query for container registries: ' + helpers.addError(registries), location);
                return rcb();
            }

            if (!registries.data.length) {
                helpers.addResult(results, 0, 'No existing container registries found', location);
                return rcb();
            }
            
            for (let registry of registries.data){
                if (!registry.id) continue;

                if (registry.identity) {
                    helpers.addResult(results, 0, 'Container registry has managed identity enabled', location, registry.id);
                } else {
                    helpers.addResult(results, 2, 'Container registry does not have managed identity enabled', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
