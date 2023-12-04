var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Diagnostic Logging Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensure diagnostic logging is enabled for enhanced monitoring and troubleshooting.',
    more_info: 'Enabling diagnostic logging provides valuable insights into SQL database performance and helps identify issues.',
    recommended_action: 'Enable diagnostic logging for SQL databases with the minimum required data recording settings: SQLInsights, ErrorsTimeouts, BlocksDeadlocks, BasicInstanceAndApp, AdvancedWorkloadManagement.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-monitoring-with-dmvs?tabs=sql-insights',
    apis: ['servers:listSql', 'databases:listByServer', 'diagnosticSettings:listByDatabase'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var recommendedDiagnosticSettings = ['Basic', 'InstanceAndAppAdvanced', 'WorkloadManagement', 'SQLInsights', 'Errors', 'Timeouts', 'Blocks', 'Deadlocks'];

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
                } else {
                    if (!databases.data.length) {
                        helpers.addResult(results, 0,
                            'No databases found for SQL server', location, server.id);
                    } else {
                        databases.data.forEach(database=> {
                            
                            var diagnosticSettings = helpers.addSource(cache, source, ['diagnosticSettings', 'listByDatabase', location, database.id]);
                        
                            if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                                helpers.addResult(results, 3, 'Unable to query diagnostic settings: ' + helpers.addError(diagnosticSettings), location, database.id);
                            } else {
                                if (!diagnosticSettings.data.length) {
                                    helpers.addResult(results, 2, 'diagnostic settings not configured for SQL database', location, database.id);
                                } else { 
                                    diagnosticSettings.data.forEach(settings=> { 
                                        var enabledDiagnosticSettings = [...settings.metrics, ...settings.logs].filter((e => e.enabled)).map((e)=>e.category);
                                        var skippedRecommendedSettings = recommendedDiagnosticSettings.filter((e) => !enabledDiagnosticSettings.includes(e));
                                        if (skippedRecommendedSettings.length) {
                                            helpers.addResult(results, 2, 'diagnostic settings are not configured with minimum requirements', location, settings.id);
                                        } else {
                                            helpers.addResult(results, 0,
                                                'Diagnostic settings are configured with minimum requirements', location, settings.id);
                                        }
                                    });

                                }
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
