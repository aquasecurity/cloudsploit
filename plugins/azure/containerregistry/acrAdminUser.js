var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'ACR Admin User',
    category: 'Container Registry',
    description: 'Ensures that the admin user is not enabled on container registries',
    more_info: 'Azure Container Registries have an admin user that is designed for testing. This should be disabled by default to avoid sharing confidential admin credentials.',
    recommended_action: 'Ensure that the admin user is disabled for each container registry.',
    link: 'https://docs.microsoft.com/en-us/azure/container-registry/container-registry-authentication',
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

            registries.data.forEach(registry => {
                if (registry.adminUserEnabled) {
                    helpers.addResult(results, 2,
                        'Admin user is enabled on the container registry', location, registry.id);
                } else {
                    helpers.addResult(results, 0,
                        'Admin user is not enabled on the container registry', location, registry.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};