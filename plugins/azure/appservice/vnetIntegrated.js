var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps VNet Integrated',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Web Apps have virtual network integrated.',
    more_info: 'Enabling virtual network integration for apps allows outbound access to resources within the virtual network, ensuring enhanced security and operational control. This feature is crucial for proactively safeguarding your server against potential security threats and unauthorized access.',
    recommended_action: 'Ensure virtual network is integrated for all web apps.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-vnet-integration',
    apis: ['webApps:list'],
    realtime_triggers: ['microsoftweb:sites:write', 'microsoftweb:sites:networkconfig:delete', 'microsoftweb:sites:delete'],

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
                    helpers.addResult(results, 0, 'Virtual Networks cannot be integrated with function apps', location, webApp.id);
                } else if (webApp && webApp.virtualNetworkSubnetId) {
                    helpers.addResult(results, 0, 'App Service is integrated with a virtual network', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'App Service is not integrated with a virtual network', location, webApp.id);
                }
            });
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
