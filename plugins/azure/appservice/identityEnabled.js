var async = require('async');

var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Identity Enabled',
    category: 'App Service',
    description: 'Ensures a system or user assigned managed identity is enabled to authenticate to App Service without storing credentials in the code.',
    more_info: 'Managing credentials in your code for authenticating to cloud services is a challenge, and maintaining the credentials secure is very important. Ideally, the credentials never appear on developer workstations and aren\'t checked into source control. The managed identities for Azure resources provides Azure services with an automatically managed identity in Azure AD. You can use the identity to authenticate to any service that supports Azure AD authentication, without having to include any credentials in your code.',
    recommended_action: 'In your App Service go to Identity > System assigned and set it to On (Enabled) or go to the User assigned tab and add a user assigned managed identity.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/overview-managed-identity',
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

            var noWebAppIdentity = [];

            webApps.data.forEach(function(webApp){
                if (!webApp.identity){
                    noWebAppIdentity.push(webApp.id);
                }
            });

            if (noWebAppIdentity.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App services do not have an Identity assigned', location);
            } else if (noWebAppIdentity.length) {
                for (app in noWebAppIdentity) {
                    helpers.addResult(results, 2, 'App service does not have an Identity assigned', location, noWebAppIdentity[app]);
                }
            } else {
                helpers.addResult(results, 0, 'All App services have identities assigned', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
