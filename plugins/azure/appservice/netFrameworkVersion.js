const async = require('async');
const helpers = require('../../../helpers/azure');
'Keeping .NET framework versions up to date ensures you have the security updates and additional functionality.'
module.exports = {
    title: '.NET Framework Version',
    category: 'App Service',
    description: 'Ensure .NET Framework is up to date for all App Services.',
    more_info: 'Keeping your .NET framework up to date will reduce the security risk vulnerabilities due to missing security patches.',
    recommended_action: 'Update .NET framwork version on all .NET App Services.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-configure',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestNetFrameworkVersion: {
            name: 'Latest .NET Framework',
            default: 4.0
        }
    },
    run: function (cache, settings, callback) {

        const configuration = {
            latestNetFrameworkVersion: settings.latestNetFrameworkVersion || this.settings.latestNetFrameworkVersion.default
        };

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

            var netFrameworkCheck = [];

            webApps.data.forEach(function(webApp){
                if (parseFloat(webApp.netFrameworkVersion.substr(1)) < configuration.latestNetFrameworkVersion) {
                    netFrameworkCheck.push({'id':webApp.id, 'version':webApp.netFrameworkVersion});
                }
            });

            if (netFrameworkCheck.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App services have an outdated .NET Framework', location);
            } else if (netFrameworkCheck.length) {
                for (app in netFrameworkCheck) {
                    helpers.addResult(results, 2, `.NET Framework version is outdated (${netFrameworkCheck[app].version})`, location, netFrameworkCheck[app].id);
                }
            } else {
                helpers.addResult(results, 0, 'All .NET App services are running on the latest framework version', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
