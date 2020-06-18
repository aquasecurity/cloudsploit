const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Authentication Enabled',
    category: 'App Service',
    description: 'Ensures Authentication is enabled for App Services, redirecting unauthenticated users to the login page.',
    more_info: 'Enabling authentication will redirect all unauthenticated requests to the login page. It also handles authentication of users with specific providers (Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter).',
    recommended_action: 'Enable App Service Authentication for all App Services.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/overview-authentication-authorization',
    apis: ['webApps:list', 'webApps:getAuthSettings'],
    compliance: {
        hipaa: 'HIPAA requires all application access to be restricted to known users ' +
               'for auditing and security controls.',
        pci: 'Access to system components must be restricted to known users.'
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
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(function(webApp) {
                const authSettings = helpers.addSource(
                    cache, source, ['webApps', 'getAuthSettings', location, webApp.id]
                );
                
                if (!authSettings || authSettings.err || !authSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(authSettings),
                        location, webApp.id);
                } else {
                    if (authSettings.data.enabled) {
                        helpers.addResult(results, 0, 'App Service has App Service Authentication enabled', location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have App Service Authentication enabled', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
