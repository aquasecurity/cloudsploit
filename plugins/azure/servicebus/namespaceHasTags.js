var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Service Bus Namespace Has Tags',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensure that Azure Service Bus namespaces have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Service Bus namespace and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['serviceBus:listNamespacesBySubscription'],
    realtime_triggers: ['microsoftservicebus:namespaces:write','microsoftservicebus:namespaces:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.serviceBus, function(location, rcb) {
            const namespaces = helpers.addSource(cache, source,
                ['serviceBus', 'listNamespacesBySubscription', location]);

            if (!namespaces) return rcb();

            if (namespaces.err || !namespaces.data) {
                helpers.addResult(results, 3, 'Unable to query Service Bus namespaces: ' + helpers.addError(namespaces), location);
                return rcb();
            }

            if (!namespaces.data.length) {
                helpers.addResult(results, 0, 'No existing Service Bus namespaces found', location);
                return rcb();
            }

            for (let namespace of namespaces.data) {
                if (!namespace.id) continue;

                if (namespace.tags && Object.entries(namespace.tags).length > 0) {
                    helpers.addResult(results, 0, 'Service Bus Namespace has tags', location, namespace.id);
                } else {
                    helpers.addResult(results, 2, 'Service Bus Namespace does not have tags', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};