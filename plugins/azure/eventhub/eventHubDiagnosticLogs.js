var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hubs Namespace Diagnostic Logs',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures that Event Hubs namespace has diagnostic logs enabled.',
    more_info: 'Enabling diagnostics logs for Event Hubs namespace helps to gain insights into the service operation and troubleshoot performance issues. This helps identifying security threats and recreate activity trails to use for investigation purposes.',
    recommended_action: 'Enable diagnostic logs for all the Event Hubs namespaces.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/monitor-event-hubs',
    apis: ['eventHub:listEventHub','diagnosticSettings:listByEventHubs'],
    realtime_triggers: ['microsofteventhub:namespaces:write', 'microsofteventhub:namespaces:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
    
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

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByEventHubs', location, eventHub.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Event Hubs namespace diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, eventHub.id);
                    continue;
                }
    
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
    
                if (found) {
                    helpers.addResult(results, 0, 'Event Hubs namespace has diagnostic logs enabled', location, eventHub.id);
                } else {
                    helpers.addResult(results, 2, 'Event Hubs namespace does not have diagnostic logs enabled', location, eventHub.id);
                }    
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
