var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Private Endpoints Configured',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Web Apps and Function Apps are accessible only through private endpoints.',
    more_info: 'Enabling private endpoints for Azure App Service and Function Apps enhances security by allowing access exclusively through a private network, minimizing the risk of public internet exposure and protecting against external attacks.',
    recommended_action: 'Ensure that Private Endpoints are configured properly and Public Network Access is disabled for Web Apps and Function Apps.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-private-endpoint',
    apis: ['webApps:list', 'webApps:getWebAppDetails'],
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
                if (!webApp || !webApp.id) return;

                const webAppDetails = helpers.addSource(cache, source,
                    ['webApps', 'getWebAppDetails', location, webApp.id]);

                let hasPrivateEndpoints = false;

                if (webAppDetails && !webAppDetails.err && webAppDetails.data && webAppDetails.data.privateEndpointConnections) {
                    if (Array.isArray(webAppDetails.data.privateEndpointConnections) && webAppDetails.data.privateEndpointConnections.length > 0) {
                        hasPrivateEndpoints = true;
                    }
                }

                if (!hasPrivateEndpoints && webApp.privateEndpointConnections && webApp.privateEndpointConnections.length > 0) {
                    hasPrivateEndpoints = true;
                }

                if (hasPrivateEndpoints) {
                    if (webApp.kind && webApp.kind.toLowerCase().includes('functionapp')) {
                        helpers.addResult(results, 0, 'Function App has Private Endpoints configured', location, webApp.id);
                    } else {
                        helpers.addResult(results, 0, 'App Service has Private Endpoints configured', location, webApp.id);
                    }
                } else {
                    // No private endpoints configured
                    if (webApp.kind && webApp.kind.toLowerCase().includes('functionapp')) {
                        helpers.addResult(results, 2, 'Function App does not have Private Endpoints configured', location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have Private Endpoints configured', location, webApp.id);
                    }
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
