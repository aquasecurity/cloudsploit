var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Trusted Services Enabled',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that "Allow trusted Microsoft services to access this container registry" feature is enabled for Azure Container registries.',
    more_info: 'Enabling network firewall rules for container registry will block access to incoming requests for data, including from other Azure services. To allow certain Azure cloud services access your vault resources, add an exception so that the trusted cloud services can bypass the firewall rules.',
    recommended_action: 'Ensure that Azure Container registry network firewall configuration allows trusted Microsoft services to bypass the firewall.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/allow-access-trusted-services',
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

                if (registry.networkRuleBypassOptions && registry.networkRuleBypassOptions.toLowerCase() === 'none'){
                    helpers.addResult(results, 2, 'Trusted Microsoft services are not allowed to access the Container registry', location, registry.id);
                } else {
                    helpers.addResult(results, 0, 'Trusted Microsoft services are allowed to access the Container registry', location, registry.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
