var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Managed Identity',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that Azure Service Bus namespaces have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify Service Bus namespace and enable managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/service-bus-managed-service-identity',
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
                } else if (namespace.identity && namespace.identity.type) {
                    helpers.addResult(results, 0, 'Service bus namespace has managed identity enabled', location, namespace.id);
                } else {
                    helpers.addResult(results, 2, 'Service bus namespace does not have managed identity enabled', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};