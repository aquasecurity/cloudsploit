var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Public Access',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures that Azure Service Bus namespaces are not publicly accessible.',
    more_info: 'Using private endpoints for Azure Service Bus namespace improve security by enabling private network access, encrypting communication, and enhancing performance. They seamlessly integrate with virtual networks, ensuring compliance and suitability for hybrid cloud scenarios.',
    recommended_action: 'Ensure that Azure Service Bus namespaces are only accessible through private endpoints.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/private-link-service',
    apis: ['serviceBus:listNamespacesBySubscription'],
    realtime_triggers: ['microsoftservicebus:namespaces:write','microsoftservicebus:namespaces:delete'],

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
                if (namespace.sku && namespace.sku.tier && namespace.sku.tier.toLowerCase() !== 'premium') {
                    helpers.addResult(results, 0, 'Service Bus Namespace is not a premium namespace', location, namespace.id);
                } else if (namespace.publicNetworkAccess && namespace.publicNetworkAccess.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 2, 'Service bus namespace is publicly accessible', location, namespace.id);
                } else {
                    helpers.addResult(results, 0, 'Service bus namespace is only accessible through private endpoints', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};