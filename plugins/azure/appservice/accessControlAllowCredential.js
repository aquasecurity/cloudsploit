const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Access Control Allow Credential Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Esures that App Service has Access Control Allow Credentials enabled with CORS',
    more_info: 'Enabling Access-Control-Allow-Credentials with  CORS (Cross-Origin Resource Sharing)ensures secure access to resources across different domains. This is crucial for handling credentials like cookies, authorization headers, or TLS client certificates in frontend JavaScript code.',
    recommended_action: 'Enable Access Control Allow Credentials for all App Services.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/app-service-web-tutorial-rest-api',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete'],

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

            for (let webApp of webApps.data) {

                const configs = helpers.addSource(cache, source, 
                    ['webApps', 'listConfigurations', location, webApp.id]);

                if (!configs || configs.err || !configs.data || !configs.data.length) {
                    helpers.addResult(results, 3, 'Unable to query for Web App Configs: ' + helpers.addError(configs), location);
                    return;
                }

                if (configs.data[0].cors && configs.data[0].cors.supportedCredentials) {
                    helpers.addResult(results, 0,
                        'App Service has Access Control Allow Credentials enabled with CORS', location, webApp.id);
                } else {
                    helpers.addResult(results, 2,
                        'App Service does not have Access Control Allow Credentials enabled with CORS', location, webApp.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
