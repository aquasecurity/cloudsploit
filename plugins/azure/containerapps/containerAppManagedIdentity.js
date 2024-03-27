var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Containe Apps Managed Identity',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Azure Container Apps has managed identity enabled.',
    more_info: 'Enabling managed identity for Azure Container Apps automates credential management, enhancing security by avoiding hard-coded credentials and simplifying access control to Azure services.',
    recommended_action: 'Enable system or user-assigned identities for all Azure Container Apps.',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/managed-identity?tabs=portal%2Cdotnet',
    apis: ['containerApps:list'],
    realtime_triggers: ['microsoftapp:containerapps:write', 'microsoftapp:containerapps:delete'],

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
                if (container.identity && container.identity.type && 
                    (container.identity.type.toLowerCase() === 'systemassigned' || container.identity.type.toLowerCase() === 'userassigned')) {
                    helpers.addResult(results, 0,
                        'Container app has managed identity enabled', location, container.id);
                } else {
                    helpers.addResult(results, 2,
                        'Container app does not have managed identity enabled', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};