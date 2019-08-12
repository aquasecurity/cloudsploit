const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'HTTP 2.0 Enabled',
    category: 'App Service',
    description: 'Ensures the latest HTTP version is enabled for the App Service.',
    more_info: 'Enabling HTTP2.0 ensures that the App Service has the latest technology which includes security enhancements and additional functionality.',
    recommended_action: 'In your App Service go to configuration > go to the General Settings tab  > select in Http Version version 2.0',
    link: 'https://azure.microsoft.com/en-us/blog/announcing-http-2-support-in-azure-app-service/',
    apis: ['webApps:list', 'webApps:listConfigurations'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {

            const webApps = helpers.addSource(
                cache, source, ['webApps', 'listConfigurations', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query App services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App services', location);
                return rcb();
            }

            let noWebAppHttp20 = [];

            webApps.data.forEach(function (webApp) {
                if (!webApp.http20Enabled) {
                    noWebAppHttp20.push(webApp.id);
                }
            });

            if (noWebAppHttp20.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App Services do not have HTTP 2.0 enabled', location);
            } else if (noWebAppHttp20.length) {
                for (app in noWebAppHttp20) {
                    helpers.addResult(results, 2, 'The App Service does not have HTTP 2.0 enabled', location, noWebAppHttp20[app]);
                }
            } else {
                helpers.addResult(results, 0, 'All App Services have HTTP 2.0 enabled', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
