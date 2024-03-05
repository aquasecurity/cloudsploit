var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Web Apps Backup Retention Period',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Azure Web Apps have recommended backup retention period.',
    more_info: 'Retaining application backups for a longer period of time will allow you to handle your app data restoration process more efficiently.',
    recommended_action: 'Configure backup retention period for Azure Web Apps',
    link: 'https://learn.microsoft.com/en-us/azure/app-service/manage-backup',
    apis: ['webApps:list', 'webApps:getBackupConfiguration'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete','microsoftweb:sites:config:write','microsoftweb:sites:config:delete'],
    settings: {
        webapps_backup_retention_period: {
            name: 'Backup retention period in days',
            description: 'Backup retention period for web apps in days.',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 7
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var webapps_backup_retention_period = parseInt(settings.webapps_backup_retention_period || this.settings.webapps_backup_retention_period.default); 

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

            webApps.data.forEach(webApp => {
                if (webApp && webApp.kind && webApp.kind === 'functionapp') {
                    helpers.addResult(results, 0, 'WebApps backup can not be configured for the function App', location, webApp.id);
                    return;
                }
                const configs = helpers.addSource(cache, source,
                    ['webApps', 'getBackupConfiguration', location, webApp.id]);

                if (configs && configs.err && configs.err.includes('NotFound')) {
                    helpers.addResult(results, 0, 'Backups are not configured for WebApp', location, webApp.id);
                } else if (!configs || configs.err || !configs.data) {
                    helpers.addResult(results, 3, 'Unable to query for Web App backup configs: ' + helpers.addError(configs), location, webApp.id);
                } else {
                    const { backupSchedule } = configs.data;
                    if (backupSchedule && backupSchedule.retentionPeriodInDays) {
                        if (backupSchedule.retentionPeriodInDays >= webapps_backup_retention_period) {
                            helpers.addResult(results, 0,
                                `WebApp has a backup retention period of ${backupSchedule.retentionPeriodInDays} of ${webapps_backup_retention_period} days limit`,
                                location, webApp.id);
                        } else {
                            helpers.addResult(results, 2,
                                `WebApp has a backup retention period of ${backupSchedule.retentionPeriodInDays} of ${webapps_backup_retention_period} days limit`,
                                location, webApp.id);
                        }
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
