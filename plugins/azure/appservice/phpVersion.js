var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'PHP Version',
    category: 'App Service',
    description: 'Ensure the latest version of PHP is installed on all App Services.',
    more_info: 'Installing the latest version of PHP will reduce the security risk of missing security patches.',
    recommended_action: '1. Enter App Services. 2. Select the App Service. 3. Select the Configuration blade under Settings. 4. Choose the General Settings Tab. 5. Select the PHP Stack and ensure that Version is the latest Version.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/web-sites-php-configure',
    apis: ['webApps:list', 'webApps:listConfigurations'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {

            var webApps = helpers.addSource(cache, source, 
                ['webApps', 'listConfigurations', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query App Service: ' + helpers.addError(webApps), location);
                return rcb();
            };

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Service', location);
                return rcb();
            };

            webApps.data.forEach(webApp => {
                if (!webApp.phpVersion || webApp.phpVersion == "") {
                    helpers.addResult(results, 0, 'No PHP version set', location, webApp.id);
                } else if (parseFloat(webApp.phpVersion) >= 7.3) {
                    helpers.addResult(results, 0, 
                        `The PHP version (${webApp.phpVersion}) is the latest version`, location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 
                        `The PHP version (${webApp.phpVersion}) is not the latest version`, location, webApp.id);
                };
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
