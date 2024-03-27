var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Container Apps HTTPS only',
    category: 'Container Apps',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensures Container Apps are only accessible over HTTPS.',
    more_info: 'Using HTTPS guarantees that server/service authentication is established and shields data during transmission from potential network eavesdropping. Disabling allowInsecure triggers automatic redirection of HTTP requests to secure HTTPS connections, ensuring container apps are securely accessed.',
    recommended_action: 'Modify Container app and disable allowInsecure setting in Ingress',
    link: 'https://learn.microsoft.com/en-us/azure/container-apps/ingress-how-to?pivots=azure-cli#ingress-settings',
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
                if (container.configuration.ingress && container.configuration.ingress.allowInsecure) {
                    helpers.addResult(results, 2,
                        'Container app is not only accessible over HTTPS', location, container.id);
                    
                } else {
                    helpers.addResult(results, 0,
                        'Container app is only accessible over HTTPS', location, container.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};