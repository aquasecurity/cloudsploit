var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Private Endpoints Configured',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures that Azure Container registries are accessible only through private endpoints',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. Private Endpoint uses a private IP address from your VNet, effectively bringing the service such as Azure SQL Server into your VNet.',
    recommended_action: 'Ensure that Private Endpoints are configured properly for Azure Container registry.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/container-registry-private-link',
    apis: ['registries:list'],
    realtime_triggers: ['microsoftcontainerregistry:registries:write','microsoftcontainerregistry:registries:delete'],

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
                helpers.addResult(results, 0, 'No existing Container registries found', location);
                return rcb();
            }

            for (let registry of registries.data){
                if (!registry.id) continue;

                if (registry.privateEndpointConnections && registry.privateEndpointConnections.length){
                    helpers.addResult(results, 0, 'Private Endpoints are configured for Container registry', location, registry.id);
                } else {
                    helpers.addResult(results, 2, 'Private Endpoints are not configured for Container registry', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
