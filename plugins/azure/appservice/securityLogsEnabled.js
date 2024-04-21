const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Security Logging Enabled',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that security logging is enabled for Azure Web Apps.',
    more_info: 'Enabling Azure Web Apps diagnostics logging provides a quick and easy way to view application logs, allowing users to diagnose and resolve issues, including errors, performance bottlenecks, and security concerns.',
    recommended_action: 'Modify Web Apps and enable diagnostic settings for all logs.',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/overview-monitoring',
    apis: ['webApps:list', 'diagnosticSettings:listByAppServices'],
    settings: {
        app_service_diagnostic_logs: {
            name: 'App Service Diagnostic Logs Enabled',
            description: 'Comma separated list of diagnostic logs that should be enabled at minimum i.e. AppServiceAntivirusScanAuditLogs, AppServiceHTTPLogs etc. If you have enabled allLogs, then resource produces pass result. If you only want to check if logging is enabled or not, irrespecitve of log type, then add * in setting.',
            regex: '^.*$',
            default: 'AppServiceAntivirusScanAuditLogs, AppServiceHTTPLogs, AppServiceConsoleLogs, AppServiceAppLogs, AppServiceFileAuditLogs,AppServiceAuditLogs, AppServiceIPSecAuditLogs, AppServicePlatformLogs'
        },
    },
    realtime_triggers: ['microsoftweb:sites:write', 'microsoftinsights:diagnosticsettings:write', 'microsoftinsights:diagnosticsettings:delete', 'microsoftweb:sites:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        var config = {
            app_service_diagnostic_logs: settings.app_service_diagnostic_logs || this.settings.app_service_diagnostic_logs.default,
        };

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

                if (webApp && webApp.kind && webApp.kind.startsWith('functionapp')) return;

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByAppServices', location, webApp.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for App Service diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, webApp.id);
                    return;
                }
                var found = true;
                var missingLogs = [];
                
                if (config.app_service_diagnostic_logs == '*') {
                    found = diagnosticSettings.data.some(ds => ds.logs && ds.logs.length);
                } else {
                    config.app_service_diagnostic_logs = config.app_service_diagnostic_logs.replace(/\s/g, '');
                    missingLogs = config.app_service_diagnostic_logs.toLowerCase().split(',');
                    diagnosticSettings.data.forEach(settings => {
                        const logs = settings.logs;
                        missingLogs = missingLogs.filter(requiredCategory =>
                            !logs.some(log => (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                        );
                    });
                }

                if (!missingLogs.length && found) {
                    helpers.addResult(results, 0, 'Web App has security logging enabled', location, webApp.id);

                } else {
                    helpers.addResult(results, 2, `Web App does not have security logging enabled ${missingLogs.length ? `for following: ${missingLogs}` : ''}`, location, webApp.id);
                }

            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
