const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Service Diagnostic Logging Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that diagnostic logging is enabled for Azure App Service.',
    more_info: 'Enabling diagnostic logging provides a quick and easy way to view application logs, allowing users to diagnose and resolve issues including errors, performance bottlenecks, and security concerns.',
    recommended_action: 'Enable diagnostic logging for all App Services.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs',
    apis: ['webApps:list', 'diagnosticSettings:listByAppServices'],
    realtime_triggers: ['microsoftweb:sites:write', 'microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete', 'microsoftweb:sites:delete'],
   
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        
        async.each(locations.webApps, (location, rcb) => {

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

            webApps.data.forEach(webApp => {
                if (!webApp.id) return;

                if (webApp && webApp.kind && webApp.kind.startsWith('app')) return;

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByAppServices', location, webApp.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for App Service diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, webApp.id);
                    return;
                }
    
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
    
                if (found) {
                    helpers.addResult(results, 0, 'App Service has diagnostic logs enabled', location, webApp.id);
                } else {
                    helpers.addResult(results, 2, 'App Service does not have diagnostic logs enabled', location, webApp.id);
                }        
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
