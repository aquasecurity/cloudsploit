var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hubs Namespace Managed Identity',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensures Microsoft Azure Event Hubs namespaces have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify Event Hubs namespace and enable managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-managed-identity',
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

                if (eventHub.sku &&  eventHub.sku.tier && eventHub.sku.tier.toLowerCase() === 'basic') {
                    helpers.addResult(results, 0,
                        'Event Hubs namespace tier is basic', location, eventHub.id);
                } else {
                    if (eventHub.identity) {
                        helpers.addResult(results, 0, 'Event Hubs namespace has managed identity enabled', location, eventHub.id);
                    } else {
                        helpers.addResult(results, 2, 'Event Hubs namespace does not have managed identity enabled', location, eventHub.id);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
