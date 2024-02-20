var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Namespace Logging Enabled',
    category: 'Service Bus',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that Azure Service Bus namespaces have diagnostic logs enabled.',
    more_info: 'Diagnostic logs provide valuable insights into the operation and health of Service Bus namespaces. By enabling diagnostic logs, you can enhance visibility, easily monitor and troubleshoot and optimize messaging performance.',
    link: 'https://learn.microsoft.com/en-us/azure/service-bus-messaging/monitor-service-bus-reference',
    recommended_action: 'Modify the namespace settings and enable diagnostic logs.',
    apis: ['serviceBus:listNamespacesBySubscription', 'diagnosticSettings:listByServiceBusNamespaces'],
    realtime_triggers: ['microsoftservicebus:namespaces:write','microsoftservicebus:namespaces:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.serviceBus, function(location, rcb) {
            const namespaces = helpers.addSource(cache, source,
                ['serviceBus', 'listNamespacesBySubscription', location]);

            if (!namespaces) return rcb();


            if (namespaces.err || !namespaces.data) {
                helpers.addResult(results, 3, 'Unable to query Service Bus namespaces: ' + helpers.addError(namespaces), location);
                return rcb();
            }

            if (!namespaces.data.length) {
                helpers.addResult(results, 0, 'No Service Bus namespaces found', location);
                return rcb();
            }
            for (let namespace of namespaces.data) {
                if (!namespace.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByServiceBusNamespaces', location, namespace.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for namespace diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, namespace.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'Service Bus namespace has diagnostic logs enabled', location, namespace.id);
                } else {
                    helpers.addResult(results, 2, 'Service Bus namespace does not have diagnostic logs enabled', location, namespace.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
