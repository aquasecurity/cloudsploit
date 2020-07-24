var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Java Version',
    category: 'App Service',
    description: 'Ensures the latest version of Java is installed for all App Services',
    more_info: 'Installing the latest version of Java will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of Java for all Java-based App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-get-started-java',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestJavaVersion: {
            name: 'Latest Java Version',
            default: 1.8,
            description: 'The latest Java version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            latestJavaVersion: settings.latestJavaVersion || this.settings.latestJavaVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

            var found = false;

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (helpers.checkAppVersions(
                    webConfigs,
                    results,
                    location,
                    webApp.id,
                    'javaVersion',
                    config.latestJavaVersion,
                    'Java',
                    custom)
                ) {
                    found = true;
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with Java found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
