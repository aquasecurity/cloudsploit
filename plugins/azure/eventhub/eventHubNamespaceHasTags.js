var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hubs Namespace Has Tags',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure that Event Hubs namespace have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify affected Event Hub namespace and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['eventHub:listEventHub'],
    realtime_triggers: ['microsofteventhub:namespaces:write', 'microsofteventhub:namespaces:delete','microsoftresources:tags:write'],

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

                if (eventHub.tags && Object.entries(eventHub.tags).length > 0){
                    helpers.addResult(results, 0,
                        'Event Hubs namespace has tags associated',location, eventHub.id);
                } else {
                    helpers.addResult(results, 2,
                        'Event Hubs namespace does not have tags associated', location, eventHub.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
