var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Private Endpoints Configured',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensures thatWeb Apps are accessible only through private endpoints',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. Private Endpoint uses a private IP address from your VNet and provides secure connectivity between clients on private network and app',
    recommended_action: 'Ensure that Private Endpoints are configured properly and Public Network Access is disabled for Web Apps',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-private-endpoint',
    apis: ['webApps:list'],
    realtime_triggers: ['microsoftweb:sites:write', 'microsoftweb:sites:privateendpointconnectionproxies:write', 'microsoftweb:sites:privateendpointconnectionproxies:delete', 'microsoftweb:sites:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query for Web Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing Web Apps found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                if (webApp && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'Private Endpoints can not be configured for the function App', location, webApp.id);
                } else if (webApp && webApp.privateLinkIdentifiers) {
                    helpers.addResult(results, 0, 'Web App has Private Endpoints configured', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'Web App does not have Private Endpoints configured', location, webApp.id);
                }
            });
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
