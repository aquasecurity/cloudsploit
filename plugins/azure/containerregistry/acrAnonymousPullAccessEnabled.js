var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Anonymous Pull Access Enabled',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensure that anonymous pull access is not enabled for Azure container registries.',
    more_info: 'Anonymous pull access makes all registry content publicly available for read actions which can cause security risks and lead to unauthorized access to registry.',
    recommended_action: 'Modify container registry and disable anonymous pull access.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/anonymous-pull-access',
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
                helpers.addResult(results, 0, 'No existing container registries found', location);
                return rcb();
            }
            
            for (let registry of registries.data){
                if (!registry.id) continue;

                if (registry.anonymousPullEnabled) {
                    helpers.addResult(results, 2, 'Anonymous pull access is enabled for the container registry', location, registry.id);
                } else {
                    helpers.addResult(results, 0, 'Anonymous pull access is not enabled for the container registry', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
