var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Encryption At Rest with CMK',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensure that Azure Service Bus namespaces are encrypted with CMK.',
    more_info: 'Azure Service Bus allows you to encrypt data in your namespaces using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption offers enhanced security and compliance, allowing centralized management and control of encryption keys through Azure Key Vault.',
    recommended_action: 'Ensure that Azure Service Bus namespaces have CMK encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/configure-customer-managed-key',
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
                } else if (namespace.encryption && Object.keys(namespace.encryption).length) {
                    helpers.addResult(results, 0, 'Service Bus Namespace is encrypted using CMK', location, namespace.id);
                }  else {
                    helpers.addResult(results, 2, 'Service Bus Namespace is not encrypted using CMK', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};