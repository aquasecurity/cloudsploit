var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'PHP Version',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensures the latest version of PHP is installed for all App Services',
    more_info: 'Installing the latest version of PHP will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of PHP for all PHP-based App Services',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/web-sites-php-configure',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestPhpVersion: {
            name: 'Latest PHP Version',
            default: '8.2',
            description: 'The latest PHP version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete'],

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
            let found = false;
            for (let webApp of webApps.data){
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data || !webConfigs.data.length) {
                    helpers.addResult(results, 3,
                        'Unable to query for Web App Configs: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                    continue;
                }

                if (webConfigs.data[0] && webConfigs.data[0].linuxFxVersion && (webConfigs.data[0].linuxFxVersion.toLowerCase().indexOf('php') > -1)){
                    found =  true;
                    let currentVersion = webConfigs.data[0].linuxFxVersion.split('|')[1];
                    if (parseFloat(currentVersion) >= parseFloat(config.latestPhpVersion)){
                        helpers.addResult(results, 0,
                            `The PHP version (${currentVersion}) is the latest version`, location, webApp.id, custom);
                    } else {
                        helpers.addResult(results, 2,
                            `The PHP version (${currentVersion}) is not the latest version`, location, webApp.id, custom);
                    }
                }

            }
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
