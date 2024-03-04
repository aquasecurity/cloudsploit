var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Managed Identity',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures a system or user assigned managed identity is enabled to authenticate to Azure Service Bus namespace.',
    more_info: 'Maintaining cloud connection credentials in code is a security risk. Credentials should never appear on developer workstations and should not be checked into source control. Managed identities for Azure resources provides Azure services with a managed identity in Azure AD which can be used to authenticate to any service that supports Azure AD authentication, without having to include any credentials in code.',
    recommended_action: 'Enable system or user-assigned identities for all Azure Service Bus namespaces.',
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
                    helpers.addResult(results, 2, 'Service bus namespace does not have identities assigned', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};