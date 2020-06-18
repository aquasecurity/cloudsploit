const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'HTTP 2.0 Enabled',
    category: 'App Service',
    description: 'Ensures the latest HTTP version is enabled for App Services',
    more_info: 'Enabling HTTP2.0 ensures that the App Service has the latest technology which improves server performance',
    recommended_action: 'Enable HTTP 2.0 support in the general settings for all App Services',
    link: 'https://azure.microsoft.com/en-us/blog/announcing-http-2-support-in-azure-app-service/',
    apis: ['webApps:list', 'webApps:listConfigurations'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    if (webConfigs.data[0] && webConfigs.data[0].http20Enabled) {
                        helpers.addResult(results, 0, 'App Service has HTTP 2.0 enabled', location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have HTTP 2.0 enabled', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
