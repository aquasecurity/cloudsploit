const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Authentication Enabled',
    category: 'App Service',
    description: 'Ensures Authentication is enabled for your App services, redirecting unauthenticated users to the login page.',
    more_info: 'Enabling authentication will redirect all unauthenticated requests to the login page. Also handles authentication of users with specified provider (Azure Active Directory, Facebook, Google, Microsoft Account, and Twitter)',
    recommended_action: 'In your App Service go to Authentication / Authorization > Set App Service Authentication to "On" (Enabled)',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/overview-authentication-authorization',
    apis: ['webApps:list', 'webApps:getAuthSettings'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {

            const authSettings = helpers.addSource(
                cache, source, ['webApps', 'getAuthSettings', location]
            );
            if (!authSettings) return rcb();

            if (authSettings.err || !authSettings.data) {
                helpers.addResult(results, 3, 'Unable to query App Service: ' + helpers.addError(authSettings), location);
                return rcb();
            }
            if (!authSettings.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Service', location);
                return rcb();
            }

            var noWebAppAuthEnabled = [];

            authSettings.data.forEach(function(settings){
                if (!settings.enabled){
                    noWebAppAuthEnabled.push(settings.id);
                }
            });

            if (noWebAppAuthEnabled.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App Services do not have App Service Authentication enabled', location);
            } else if (noWebAppAuthEnabled.length) {
                for (settings in noWebAppAuthEnabled) {
                    helpers.addResult(results, 2, 'App Service does not have App Service Authentication enabled', location, noWebAppAuthEnabled[settings]);
                }
            } else {
                helpers.addResult(results, 0, 'All App Services have App Service Authentication enabled', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
