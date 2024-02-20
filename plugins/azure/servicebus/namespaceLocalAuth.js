var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Local Authentication Disabled',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensures local authentication is disabled for Service Bus namespaces.',
    more_info: 'For enhanced security, centralized identity management, and seamless integration with Azure\'s authentication and authorization services, it is recommended to rely on Azure Active Directory (Azure AD) and disable local authentication (shared access policies) in Azure Service Bus namespaces.',
    recommended_action: 'Ensure that Azure Service Bus namespaces have local authentication disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/disable-local-authentication',
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
                if (namespace.disableLocalAuth) {
                    helpers.addResult(results, 0, 'Service Bus Namespace has local authentication disabled', location, namespace.id);
                }  else {
                    helpers.addResult(results, 2, 'Service Bus Namespace has local authentication enabled', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};