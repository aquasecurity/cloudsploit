
var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hubs Namespace Auto Inflate Enabled',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that Event Hubs namespace have Auto Inflate feature enabled',
    more_info: 'Enabling Auto-inflate for your Azure Event Hubs namespace ensures seamless scaling by automatically adjusting the number of throughput units (TUs) based on workload demands. This feature helps prevent throttling issues by scaling up as needed, providing efficient and reliable data handling without manual intervention.',
    recommended_action: 'Modify Event Hub namespace and enable auto-inflate feature.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/event-hubs-auto-inflate',
    apis: ['eventHub:listEventHub'],
    realtime_triggers: ['microsofteventhub:namespaces:write', 'microsofteventhub:namespaces:delete'],

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

                if (eventHub.sku && 
                    eventHub.sku.tier && 
                    eventHub.sku.tier.toLowerCase() != 'standard') continue;

                if (eventHub.isAutoInflateEnabled){
                    helpers.addResult(results, 0,
                        'Event Hubs namespace has auto inflate feature enabled',location, eventHub.id);
                } else {
                    helpers.addResult(results, 2,
                        'Event Hubs namespace does not have auto inflate feature enabled', location, eventHub.id);
                }
            }
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
