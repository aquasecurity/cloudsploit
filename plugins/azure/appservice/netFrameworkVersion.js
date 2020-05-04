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
            default: 4.0,
            description: 'The latest NET version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },
    run: function (cache, settings, callback) {
        const config = {
            latestNetFrameworkVersion: settings.latestNetFrameworkVersion || this.settings.latestNetFrameworkVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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
                    'Unable to query App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            var found = false;

            webApps.data.forEach(webApp => {
                if (webApp.netFrameworkVersion && webApp.netFrameworkVersion !== "") {
                    found = true;

                    if (parseFloat(webApp.netFrameworkVersion.substr(1)) >= config.latestNetFrameworkVersion) {
                        helpers.addResult(results, 0, 
                            `The .NET framework version (${parseFloat(webApp.netFrameworkVersion)}) is the latest version`, location, webApp.id, custom);
                    } else {
                        helpers.addResult(results, 2, 
                            `The .NET framework version (${parseFloat(webApp.netFrameworkVersion)}) is not the latest version`, location, webApp.id, custom);
                    }
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with the .NET framework found', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
