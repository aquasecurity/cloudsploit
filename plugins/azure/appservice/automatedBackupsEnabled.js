var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Backup Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensures that Azure Web Apps have automated backups enabled.',
    more_info: 'Protect your Azure App Services web applications against accidental deletion and/or corruption, you can configure application backups to create restorable copies of your app content.',
    recommended_action: 'Configure backup for Azure Web Apps',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/manage-backup',
    apis: ['webApps:list', 'webApps:getBackupConfiguration'],

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

            async.each(webApps.data, function(webApp, scb) {
                if (webApp && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'WebApps backup can not be configured for the function App', location, webApp.id);
                    return scb();
                }

                const configs = helpers.addSource(cache, source,
                    ['webApps', 'getBackupConfiguration', location, webApp.id]);

                if (configs && configs.err) {
                    helpers.addResult(results, 3, 'Unable to query for Web App backup configs: ' + helpers.addError(configs), location);
                    return scb();
                }

                if (!configs || !configs.data) {
                    helpers.addResult(results, 2, 'Backups are not configured for WebApp', location, webApp.id);
                } else {
                    helpers.addResult(results, 0, 'Backups are configured for WebApp', location, webApp.id);
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
