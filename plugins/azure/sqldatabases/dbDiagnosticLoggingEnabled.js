var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Database Diagnostic Logging Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures diagnostic logging is enabled for SQL databases.',
    more_info: 'Enabling diagnostic logging provides valuable insights into SQL database that helps to monitor resources for their availability, performance, and operation.',
    recommended_action: 'Enable diagnostic logging for all SQL databases.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/monitoring-sql-database-azure-monitor?view=azuresql',
    apis: ['servers:listSql', 'databases:listByServer', 'diagnosticSettings:listByDatabase'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],
    settings: {
        sqldb_diagnostic_logs: {
            name: 'Diagnostic Logs Enabled',
            description: 'Comma separated list of diagnostic logs that should be enabled at minimum i.e. SQLInsights, AutomaticTuning, Errors etc. If you have enabled allLogs, then resource produces pass result. If you only want to check if logging is enabled or not, irrespecitve of log type, then add * in setting.',
            regex: '^.*$',
            default: 'SQLInsights, Errors, Timeouts, Blocks, Deadlocks'

        },
        sqldb_diagnostic_metrics: {
            name: 'Diagnostic Metrics Enabled',
            description: 'Comma separated list of diagnostic metrics that should be enabled at minimum i.e. Basic, InstanceAndAppAdvanced, WorkloadManagement. If you only want to check if mertics is enabled or not, irrespecitve of metric type, then add * in setting.',
            regex: '^.*$',
            default: 'Basic, InstanceAndAppAdvanced, WorkloadManagement'

        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var logsConfig = settings.sqldb_diagnostic_logs || this.settings.sqldb_diagnostic_logs.default;
        var metricsConfig = settings.sqldb_diagnostic_metrics || this.settings.sqldb_diagnostic_metrics.default;


        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source, ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3, 'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                var databases = helpers.addSource(cache, source,
                    ['databases', 'listByServer', location, server.id]);

                if (!databases || databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server databases: ' + helpers.addError(databases), location, server.id);
                    return;
                }
                if (!databases.data.length) {
                    helpers.addResult(results, 0,
                        'No databases found for SQL server', location, server.id);
                    return;

                } else {
                    databases.data.forEach(database=> {

                        if (database.name && database.name.toLowerCase() !== 'master') {

                            var diagnosticSettings = helpers.addSource(cache, source, ['diagnosticSettings', 'listByDatabase', location, database.id]);

                            if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                                helpers.addResult(results, 3, 'Unable to query SQL database diagnostic settings: ' + helpers.addError(diagnosticSettings), location, database.id);
                                return;

                            }
                            var foundLogs = true;
                            var foundMetrics = true;

                            var missingLogs = [];
                            var missingMetrics = [];
                            var missingConfig = [];

                            if (logsConfig == '*') {
                                foundLogs = diagnosticSettings.data.some(ds => ds.logs && ds.logs.length && ds.logs.some(log=>log.enabled));
                            } else {
                                logsConfig = logsConfig.replace(/\s/g, '');
                                missingLogs = logsConfig.toLowerCase().split(',');
                                diagnosticSettings.data.forEach(settings => {
                                    missingLogs = missingLogs.filter(requiredCategory =>
                                        !settings.logs.some(log => (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) || log.categoryGroup && log.categoryGroup.toLowerCase() === 'alllogs' && log.enabled)
                                    );
                                });
                            }
                            if (metricsConfig == '*') {
                                foundMetrics = diagnosticSettings.data.some(ds => ds.metrics && ds.metrics.length && ds.metrics.some(metrics=>metrics.enabled));
                            } else {
                                metricsConfig = metricsConfig.replace(/\s/g, '');
                                missingMetrics = metricsConfig.toLowerCase().split(',');
                                diagnosticSettings.data.forEach(settings => {
                                    missingMetrics = missingMetrics.filter(requiredCategory =>
                                        !settings.metrics.some(metric => (metric.category && metric.category.toLowerCase() === requiredCategory && metric.enabled))
                                    );
                                });
                            }
                            missingConfig = [...missingLogs, ...missingMetrics];

                            if (!missingConfig.length && foundLogs && foundMetrics) {
                                helpers.addResult(results, 0, 'SQL database has diagnostic logs/metrics enabled', location, database.id);

                            } else {
                                helpers.addResult(results, 2, `SQL database does not have diagnostic logs/metrics enabled ${missingConfig.length ? `for following: ${missingConfig.join(',')}` : ''}`, location, database.id);
                            }
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
