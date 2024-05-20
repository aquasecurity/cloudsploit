var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps Volume Mount Configured',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Container Apps are configured to use volume mounts.',
    more_info: 'Adding volume mounts in Azure Container Apps ensures persistent storage, enabling data integrity and seamless sharing among containers. By configuring volume mounts, data remains available even after container restarts or in case of failures, facilitating backup, scalability, and simplified management of applications',
    recommended_action: 'Modify Container apps and configure volume mount.',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts',
    apis: ['containerApps:list'],
    realtime_triggers: ['microsoftapp:containerapps:write', 'microsoftapp:containerapps:delete'],

    run: function(cache, settings, callback) {
        var results =  [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.containerApps, function(location, rcb) {

            var containerApps = helpers.addSource(cache, source,
                ['containerApps', 'list', location]);

            if (!containerApps) return rcb();

            if (containerApps.err || !containerApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Container apps: ' + helpers.addError(containerApps), location);
                return rcb();
            }

            if (!containerApps.data.length) {
                helpers.addResult(results, 0, 'No existing Container apps found', location);
                return rcb();
            }

            for (let container of containerApps.data) {
                if (!container.id) continue; 

                if (container.template && container.template.volumes && 
                    container.template.volumes.length ) {
                    helpers.addResult(results, 0,
                        'Container app has volume mount configured', location, container.id);
                } else {
                    helpers.addResult(results, 2,
                        'Container app does not have volume mount configured', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};