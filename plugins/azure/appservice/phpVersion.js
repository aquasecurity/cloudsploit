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
            default: 7.3
        }
    },
    run: function (cache, settings, callback) {
        const config = {
            latestPhpVersion: settings.latestPhpVersion || this.settings.latestPhpVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {
            var webApps = helpers.addSource(cache, source, 
                ['webApps', 'listConfigurations', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            var found = false;

            webApps.data.forEach(webApp => {
                if (webApp.phpVersion && webApp.phpVersion !== "") {
                    found = true;

                    if (parseFloat(webApp.phpVersion) >= config.latestphpVersion) {
                        helpers.addResult(results, 0, 
                            `The PHP version (${parseFloat(webApp.phpVersion)}) is the latest version`, location, webApp.id, custom);
                    } else {
                        helpers.addResult(results, 2, 
                            `The PHP version (${parseFloat(webApp.phpVersion)}) is not the latest version`, location, webApp.id, custom);
                    }
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with PHP found', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
