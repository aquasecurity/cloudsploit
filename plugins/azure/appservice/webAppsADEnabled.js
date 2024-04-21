var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Active Directory Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Web Apps have registration with Azure Active Directory.',
    more_info: 'Registration with Azure Active Directory (AAD) enables App Service web applications to connect to other Azure cloud services securely without the need of access credentials such as user names and passwords.',
    recommended_action: 'Enable registration with Azure Active Directory for Azure Web Apps.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-managed-identity?tabs=portal%2Chttp#add-a-system-assigned-identity',
    apis: ['webApps:list'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query for Web Apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing Web Apps found', location);
                return rcb();
            }

            for (let app of webApps.data) {
                if (app.identity && app.identity.principalId) {
                    helpers.addResult(results, 0, 'Registration with Azure Active Directory is enabled for the Web App', location, app.id);
                } else {
                    helpers.addResult(results, 2, 'Registration with Azure Active Directory is disabled for the Web App', location, app.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
