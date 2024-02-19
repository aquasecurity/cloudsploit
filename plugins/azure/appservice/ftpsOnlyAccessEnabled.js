var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'FTPS Only Access Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Web Apps have FTPS only access enabled.',
    more_info: 'FTPS-only access for your Azure App Services applications, can guarantee that the encrypted traffic between the web application servers and the FTP clients cannot be decrypted by malicious actors.',
    recommended_action: 'Enable FTPS-only access for Azure Web Apps',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/deploy-ftp?tabs=portal#enforce-ftps',
    apis: ['webApps:list', 'webApps:listConfigurations'],
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

            async.each(webApps.data, function(webApp, scb) {
                if (webApp && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'Always On feature can not be configured for the function App', location, webApp.id);
                    return scb();
                }

                const configs = helpers.addSource(cache, source,
                    ['webApps', 'listConfigurations', location, webApp.id]);

                if (!configs || configs.err || !configs.data || !configs.data.length) {
                    helpers.addResult(results, 3, 'Unable to query for Web App Configs: ' + helpers.addError(configs), location);
                    return scb();
                }

                const ftpsOnlyAcces = configs.data.every(config => config.ftpsState && config.ftpsState.toLowerCase() == 'ftpsonly');

                if (ftpsOnlyAcces) {
                    helpers.addResult(results, 0, 'FTPS-only access is enabled for the Web App', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'FTPS-only access is disabled for the Web App', location, webApp.id);
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
