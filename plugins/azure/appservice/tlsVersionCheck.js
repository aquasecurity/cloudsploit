var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'TLS Version Check',
    category: 'App Service',
    description: 'Ensure that all web apps are using the latest version of TLS.',
    more_info: 'App service currently allows the web app to set TLS versions 1.0, 1.1 and 1.2. It is highly recommended to use the latest TLS 1.2 version for web app secure connections.',
    recommended_action: '1. Enter App Services. 2. Select the Web App. 3. Select the TLS/SSL blade under settings. 4. Ensure that Minimum TLS Version is 1.2.',
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
                helpers.addResult(results, 3, 'Unable to query App Service: ' + helpers.addError(webApps), location);
                return rcb();
            };

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Service', location);
                return rcb();
            };

            webApps.data.forEach(item => {
                if (item.minTlsVersion &&
                    parseFloat(item.minTlsVersion) >= 1.2) {
                    helpers.addResult(results, 0,'Minimum TLS version criteria is satisfied', location, item.id);
                } else {
                    helpers.addResult(results, 1, 'Minimum TLS version has to be 1.2', location, item.id);
                };
            });
            
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}


