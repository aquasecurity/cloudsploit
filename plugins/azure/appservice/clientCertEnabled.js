const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Client Certificates Enabled',
    category: 'App Service',
    description: 'Ensures Client Certificates are enabled for your App Service, only allowing clients with valid certificates to reach the app',
    more_info: 'Enabling Client Certificates will block all clients who do not have a valid certificate from accessing the app.',
    recommended_action: 'In your App Service go to SSL Settings > Incoming client certificates and set it to "On" (Enabled).',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-configure-tls-mutual-auth#enable-client-certificates',
    apis: ['webApps:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {

            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
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

            let noWebAppClientCert = [];

            webApps.data.forEach(function(webApp){
                if (!webApp.clientCertEnabled){
                    noWebAppClientCert.push(webApp.id);
                }
            });

            if (noWebAppClientCert.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App Services do not have Client Certificates Enabled', location);
            } else if (noWebAppClientCert.length) {
                for (app in noWebAppClientCert) {
                    helpers.addResult(results, 2, 'The App Service does not have Client Certificates Enabled', location, noWebAppClientCert[app]);
                }
            } else {
                helpers.addResult(results, 0, 'All App Services have Client Certificates Enabled', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
