var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'ACR Public Access',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensures that Azure Container registries are not publicly accessible.',
    more_info: 'Azure Container registries should be not be publicly accessible to prevent unauthorized actions.',
    recommended_action: 'Ensure that the public network access is disabled for each container registry.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/container-registry-access-selected-networks',
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

                if (registry.publicNetworkAccess && registry.publicNetworkAccess.toLowerCase() === 'enabled'){
                    helpers.addResult(results, 2, 'Container registry is publicly accessible', location, registry.id);
                } else {
                    helpers.addResult(results, 0, 'Container registry is not publicly accessible', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
