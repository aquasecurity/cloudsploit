const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Client Certificates Enabled',
    category: 'App Service',
    description: 'Ensures Client Certificates are enabled for App Services, only allowing clients with valid certificates to reach the app',
    more_info: 'Enabling Client Certificates will block all clients that do not have a valid certificate from accessing the app.',
    recommended_action: 'Enable incoming client certificate SSL setting for all App Services.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth#enable-client-certificates',
    apis: ['webApps:list'],

    run: function(cache, settings, callback) {
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
                    'Unable to query App Service: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                if (webApp.clientCertEnabled) {
                    helpers.addResult(results, 0, 'The App Service has Client Certificates enabled', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'The App Service does not have Client Certificates enabled', location, webApp.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
