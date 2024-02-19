var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Infrastructure Encryption Enabled',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that Azure Service Bus namespaces have infrastructure level encryption enabled.',
    more_info: 'Enabling infrastructure level encryption for Azure Service Bus namespaces allows their data to be encrypted twice, once at the service level and once at the infrastructure level, using two different encryption algorithms and two different keys and provides an extra layer of protection and security in case one of the keys is compromised.',
    recommended_action: 'Enable infrastructure level encryption for all Azure Service Bus namespaces.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key#enable-infrastructure-double-encryption-of-data',
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
                } else if (namespace.encryption && Object.keys(namespace.encryption).length && namespace.encryption.requireInfrastructureEncryption) {
                    helpers.addResult(results, 0, 'Service Bus Namespace has infrastructure level encryption enabled', location, namespace.id);
                }  else {
                    helpers.addResult(results, 2, 'Service Bus Namespace does not have infrastructure level encryption enabled', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};