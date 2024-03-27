var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps Authentication Enabled',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures Authentication is enabled for Container Apps.',
    more_info: 'Enabling authentication for Container Apps enhances security by preventing unauthorized access and ensuring that only authenticated users can interact with the app.',
    recommended_action: 'Enable Authentication for Container Apps.',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/authentication',
    apis: ['containerApps:list', 'containerApps:getAuthSettings'],
    realtime_triggers: ['microsoftapp:containerapps:write', 'microsoftapp:containerapps:authconfigs:write', 'microsoftapp:containerapps:delete'],

    run: function(cache, settings, callback) {
        var results = [];
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

                var authConfig = helpers.addSource(cache, source, 
                    ['containerApps', 'getAuthSettings', location, container.id]);
 
                if (!authConfig || authConfig.err || !authConfig.data) {
                    helpers.addResult(results, 3, `Unable to query for Container app Authentication:  ${helpers.addError(authConfig)}`,
                        location, container.id);
                    continue;
                }

                if (authConfig.data[0].platform && authConfig.data[0].platform.enabled) {
                    helpers.addResult(results, 0,
                        'Container app has authentication enabled', location, container.id);
                } else {
                    helpers.addResult(results, 2,
                        'Container app does not have authentication enabled', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};