const async = require('async');

const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'HTTPS Only Enabled',
    category: 'App Service',
    description: 'Ensures HTTPS Only is enabled for App Services, redirecting all HTTP traffic to HTTPS',
    more_info: 'Enabling HTTPS Only traffic will redirect all non-secure HTTP requests to HTTPS. HTTPS uses the SSL/TLS protocol to provide a secure connection.',
    recommended_action: 'Enable HTTPS Only support SSL settings for all App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-custom-ssl#enforce-https',
    apis: ['webApps:list'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'App Service HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.',
        pci: 'All card holder data must be transmitted over secure channels. ' +
                'App Service HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.'
    },

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
                if (webApp.httpsOnly) {
                    helpers.addResult(results, 0, 'The App Service has HTTPS Only enabled', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'The App Service does not have HTTPS Only enabled', location, webApp.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
