var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'PHP Version',
    category: 'App Service',
    description: 'Ensures the latest version of PHP is installed for all App Services',
    more_info: 'Installing the latest version of PHP will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of PHP for all PHP-based App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-php-configure',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestPhpVersion: {
            name: 'Latest PHP Version',
            default: '7.3',
            description: 'The latest PHP version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },
    run: function(cache, settings, callback) {
        const config = {
            latestPhpVersion: settings.latestPhpVersion || this.settings.latestPhpVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

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

                if (helpers.checkAppVersions(webConfigs, results, location, webApp.id, 'phpVersion', config.latestPhpVersion, 'PHP', custom)
                ) {
                    found = true;
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with PHP found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
