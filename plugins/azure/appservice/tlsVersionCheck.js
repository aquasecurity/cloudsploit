var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'TLS Version Check',
    category: 'App Service',
    description: 'Ensures that all web apps are using the latest version of TLS',
    more_info: 'App Services currently allows web apps to use TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app TLS connections.',
    recommended_action: 'Set the minimum TLS version to 1.2 for all App Services.',
    link: 'https://azure.microsoft.com/en-in/updates/app-service-and-functions-hosted-apps-can-now-update-tls-versions/',
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
                helpers.addResult(results, 3, 'Unable to query App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(item => {
                if (item.minTlsVersion &&
                    parseFloat(item.minTlsVersion) >= 1.2) {
                    helpers.addResult(results, 0,'Minimum TLS version criteria is satisfied', location, item.id);
                } else {
                    helpers.addResult(results, 2, 'Minimum TLS version is not 1.2', location, item.id);
                };
            });
            
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}


