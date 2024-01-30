var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Diagnostic Logging Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures diagnostic logging is enabled for SQL databases.',
    more_info: 'Enabling diagnostic logging provides valuable insights into SQL database that helps to monitor resources for their availability, performance, and operation.',
    recommended_action: 'Enable diagnostic logging for all SQL databases.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/monitoring-sql-database-azure-monitor?view=azuresql',
    apis: ['servers:listSql', 'databases:listByServer', 'diagnosticSettings:listByDatabase'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],
    settings: {
        diagnostic_logs: {
            name: 'Diagnostic Logs Enabled',
            description: 'Comma separated list of diagnostic logs/metrics that should be enabled at minimum i.e. SQLInsights, AutomaticTuning, InstanceAndAppAdvanced etc. If you have enabled allLogs, then resource produces pass result. If you only want to check if logging is enabled or not, irrespecitve of log type, then add * in setting.',
            regex: '^.*$',
            default: 'SQLInsights, Errors, Timeouts, Blocks, Deadlocks, Basic, InstanceAndAppAdvanced, WorkloadManagement'

        },
    },
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = settings.diagnostic_logs || this.settings.diagnostic_logs.default;

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
                            
                        var diagnosticSettings = helpers.addSource(cache, source, ['diagnosticSettings', 'listByDatabase', location, database.id]);
                        
                        if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                            helpers.addResult(results, 3, 'Unable to query SQL database diagnostic settings: ' + helpers.addError(diagnosticSettings), location, database.id);
                            return;
                            
                        } 
                        var found = true;
                        var missingConfig = [];
                        if (config == '*') {
                            found = diagnosticSettings.data.some(ds => ds.logs && ds.logs.length && ds.logs.some(log=>log.enabled) || ds.metrics && ds.metrics.length && ds.metrics.some(metrics=>metrics.enabled));
                        } else {
                            config = config.replace(/\s/g, '');
                            missingConfig = config.toLowerCase().split(',');
                            diagnosticSettings.data.forEach(settings => {
                                const logs_metrics = [...settings.logs, ...settings.metrics];
                                missingConfig = missingConfig.filter(requiredCategory =>
                                    !logs_metrics.some(log => (log.category && log.category.toLowerCase() === requiredCategory && log.enabled) || log.categoryGroup === 'allLogs' && log.enabled)
                                );
                            });
        
                        }
                        if (!missingConfig.length && found) {
                            helpers.addResult(results, 0, 'SQL database has diagnostic logs enabled', location, database.id);
        
                        } else {
                            helpers.addResult(results, 2, `SQL database does not have diagnostic logs enabled ${missingConfig.length ? `for following: ${missingConfig}` : ''}`, location, database.id);
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
