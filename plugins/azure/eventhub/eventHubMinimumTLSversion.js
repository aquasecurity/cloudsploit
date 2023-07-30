var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hub Minimum TLS Version',
    category: 'Event Hubs',
    domain: 'Messaging',
    description: 'Ensures Microsoft Azure Event Hubs do not allow outdated TLS certificate versions.',
    more_info: 'TLS 1.2 or higher should be used for all TLS connections to Microsoft Azure Event Hubs.',
    recommended_action: 'Modify Event Hub to set the desired minimum TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/transport-layer-security-enforce-minimum-version',
    apis: ['eventHub:listEventHub'],
    settings: {
        event_hub_min_tls_version: {
            name: 'Event Hub Minimum TLS Version',
            description: 'Minimum desired TLS version for Microsoft Azure Event Hubs',
            regex: '^(1.0|1.1|1.2)$',
            default: '1.2'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            event_hub_min_tls_version: settings.event_hub_min_tls_version || this.settings.event_hub_min_tls_version.default
        };

        var desiredVersion = parseFloat(config.event_hub_min_tls_version);

        async.each(locations.eventHub, function(location, rcb) {
            var eventHubs = helpers.addSource(cache, source,
                ['eventHub', 'listEventHub', location]);

            if (!eventHubs) return rcb();

            if (eventHubs.err || !eventHubs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Event Hubs: ' + helpers.addError(eventHubs), location);
                return rcb();
            }

            if (!eventHubs.data.length) {
                helpers.addResult(results, 0, 'No Event Hubs found', location);
                return rcb();
            }
            for (let eventHub of eventHubs.data){

                if (!eventHub.id) continue;

                if (eventHub.minimumTlsVersion && parseFloat(eventHub.minimumTlsVersion) >= desiredVersion) {
                    helpers.addResult(results, 0,
                        `Event Hub is using TLS version ${eventHub.minimumTlsVersion} which is equal to or higher than desired TLS version ${config.event_hub_min_tls_version}`,
                        location, eventHub.id);
                } else {
                    helpers.addResult(results, 2,
                        `Event Hub is using TLS version ${eventHub.minimumTlsVersion} which is less than desired TLS version ${config.event_hub_min_tls_version}`,
                        location, eventHub.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
