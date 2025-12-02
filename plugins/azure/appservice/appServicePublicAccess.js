var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Service Public Network Access Disabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'High',
    description: 'Ensures that Azure App Services have public network access disabled to prevent exposure of the application to the internet.',
    more_info: 'By default, App Services may allow public network traffic unless explicitly disabled. Public network access can be disabled using the publicNetworkAccess property or by configuring a private endpoint. Disabling public network access ensures that your applications are only reachable through secure private endpoints and not exposed to the public internet.',
    recommended_action: 'Set the Public network access setting to Disabled in the App Service Networking configuration, or configure a private endpoint to restrict access. You can do this via the Azure Portal, CLI, or ARM template.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-access-restrictions#ip-based-access-restriction-rules',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    realtime_triggers: ['microsoftweb:sites:write', 'microsoftweb:sites:delete', 'microsoftweb:sites:config:write', 'microsoftweb:sites:config:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            var webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                if (!webApp.id) return;

                var webConfigs = helpers.addSource(cache, source,
                    ['webApps', 'listConfigurations', location, webApp.id]);

                if (!webConfigs || webConfigs.err || !webConfigs.data || !webConfigs.data.length) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service configuration: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                    return;
                }

                var config = webConfigs.data[0];

                if (config.publicNetworkAccess && config.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0,
                        'App Service has public network access disabled',
                        location, webApp.id);
                } else {
                    helpers.addResult(results, 2,
                        'App Service does not have public network access disabled',
                        location, webApp.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};