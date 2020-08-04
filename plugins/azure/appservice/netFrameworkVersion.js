const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: '.NET Framework Version',
    category: 'App Service',
    description: 'Ensures the latest version of the .NET Framework is installed for all App Services.',
    more_info: 'Installing the latest version of the .NET framework will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of the .NET framework for all .NET-based App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestNetFrameworkVersion: {
            name: 'Latest .NET Framework Version',
            default: '4.0',
            description: 'The latest NET version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },
    run: function(cache, settings, callback) {
        const config = {
            latestNetFrameworkVersion: settings.latestNetFrameworkVersion || this.settings.latestNetFrameworkVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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
                    'netFrameworkVersion',
                    config.latestNetFrameworkVersion,
                    '.NET',
                    custom)) {
                    found = true;
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with .NET found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
