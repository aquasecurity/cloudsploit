var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps HTTPS only',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures that Container Apps are only accessible over HTTPS.',
    more_info: 'Enabling ingress feature for container app redirects the non-secure HTTP requests to HTTPS ensuring that container apps are securely accessed. This allows server authentication and protects data in transit from potential security threats.',
    recommended_action: 'Enable HTTPS only by disabling allowInsecure feature for all Container apps.',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/ingress-overview',
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
                if (!container.id) continue;
                if (container.configuration && container.configuration.ingress && container.configuration.ingress.allowInsecure) {
                    helpers.addResult(results, 2,
                        'Container app is not configured with HTTPS only traffic', location, container.id);
                    
                } else {
                    helpers.addResult(results, 0,
                        'Container app is configured with HTTPS only traffic', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
