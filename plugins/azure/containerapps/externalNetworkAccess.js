var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps External Network Access',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Container Apps have external network access disabled.',
    more_info: 'Disabling external network access for Container Apps ensures that inbound communication is restricted to callers within the apps environment, enhancing security by minimizing exposure to external threats. This helps safeguard sensitive data and prevents unauthorized access to the app resources.',
    recommended_action: 'Modify all Container Apps and disable external network access.',
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

                if (container.configuration && container.configuration.ingress && container.configuration.ingress.external) {
                    helpers.addResult(results, 2,
                        'Container app does not have external network access disabled', location, container.id);

                } else {
                    helpers.addResult(results, 0,
                        'Container app has external network access disabled', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
