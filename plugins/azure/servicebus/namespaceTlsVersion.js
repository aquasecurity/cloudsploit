var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Minimum TLS Version',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Service Bus namespace is using the latest TLS version.',
    more_info: 'TLS versions 1.0 and 1.1 are known to be susceptible to attacks, and to have other Common Vulnerabilities and Exposures (CVE) weaknesses. So there\'s an industry-wide push toward the exclusive use of Transport Layer Security(TLS) version 1.2 or later.',
    recommended_action: 'Ensure that Azure Srvice Bus namespaces are using the latest TLS version',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/transport-layer-security-enforce-minimum-version',
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
                if (namespace.minimumTlsVersion && (parseFloat(namespace.minimumTlsVersion) >= 1.2)) {
                    helpers.addResult(results, 0, 'Service Bus namespace is using the latest TLS Version', location, namespace.id);
                } else {
                    helpers.addResult(results, 2, 'Service Bus namespace is not using the latest TLS Version', location, namespace.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};