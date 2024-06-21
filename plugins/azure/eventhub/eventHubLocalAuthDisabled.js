var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Hub Namespace Local Auth Disabled',
    category: 'Event Hubs',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures local authentication is disabled for Event Hub namespace.',
    more_info: 'For enhanced security, centralized identity management, and seamless integration with Azure\'s authentication and authorization services, it is recommended to rely on Azure Active Directory (Azure AD) and disable local authentication in Azure Event Hubs namespaces.',
    recommended_action: 'Ensure that Azure Event Hubs namespaces have local authentication disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/event-hubs/authenticate-shared-access-signature#disabling-localsas-key-authentication',
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

                if (eventHub.disableLocalAuth) {
                    helpers.addResult(results, 0, 'Event Hubs namespace has local authentication disabled',location, eventHub.id);
                } else {
                    helpers.addResult(results, 2, 'Event Hubs namespace has local authentication enabled', location, eventHub.id);
                }
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
