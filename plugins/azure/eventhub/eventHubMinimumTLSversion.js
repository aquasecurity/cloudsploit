var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hubs Minimum TLS Version',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures Microsoft Azure Event Hubs namespaces do not allow outdated TLS certificate versions.',
    more_info: 'To enforce stricter security measures, you can configure your Event Hubs namespace to require that clients send and receive data with a newer version of TLS.',
    recommended_action: 'Modify Event Hubs namespaces to set the desired minimum TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/transport-layer-security-enforce-minimum-version',
    apis: ['eventHub:listEventHub'],
    realtime_triggers: ['microsofteventhub:namespaces:write', 'microsofteventhub:namespaces:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);


        var event_hub_min_tls_version = '1.2';


        var desiredVersion = parseFloat(event_hub_min_tls_version);

        async.each(locations.eventHub, function(location, rcb) {
            var eventHubs = helpers.addSource(cache, source,
                ['eventHub', 'listEventHub', location]);

            if (!eventHubs) return rcb();

            if (eventHubs.err || !eventHubs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Event Hubs namespaces: ' + helpers.addError(eventHubs), location);
                return rcb();
            }

            if (!eventHubs.data.length) {
                helpers.addResult(results, 0, 'No Event Hubs namespaces found', location);
                return rcb();
            }

            for (let eventHub of eventHubs.data){
                if (!eventHub.id) continue;

                if (eventHub.minimumTlsVersion && parseFloat(eventHub.minimumTlsVersion) >= desiredVersion) {
                    helpers.addResult(results, 0,
                        `Event Hubs namespace is using TLS version ${eventHub.minimumTlsVersion}`,
                        location, eventHub.id);
                } else {
                    helpers.addResult(results, 2,
                        `Event Hubs namespace is using TLS version ${eventHub.minimumTlsVersion} instead of version ${event_hub_min_tls_version}`,
                        location, eventHub.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
