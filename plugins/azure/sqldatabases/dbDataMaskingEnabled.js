var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Databases Data Masking Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures dynamic data masking is enabled for all SQL databases.',
    more_info: 'Dynamic data masking helps prevent unauthorized access to sensitive data by enabling customers to specify how much sensitive data to reveal with minimal effect on the application layer. DDM can be configured on designated database fields to hide sensitive data in the result sets of queries.',
    recommended_action: 'Enable dynamic data masking for SQL databases.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-dynamic-data-masking-get-started-portal',
    apis: ['servers:listSql', 'databases:listByServer', 'dataMaskingPolicies:get'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:delete'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

            // Loop through servers and check databases
            servers.data.forEach(server => {
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
                        databases.data.forEach(database =>  {
                            
                            var dataMaskingPolicies = helpers.addSource(cache, source, ['dataMaskingPolicies', 'get', location, database.id]);
                            
                            if (!dataMaskingPolicies || dataMaskingPolicies.err || !dataMaskingPolicies.data || !dataMaskingPolicies.data) {
                                helpers.addResult(results, 3, 'Unable to query dynamic data masking policies: ' + helpers.addError(dataMaskingPolicies), location, database.id);
                            } else {
                                if (dataMaskingPolicies.data.dataMaskingState && dataMaskingPolicies.data.dataMaskingState.toLowerCase() == 'enabled') {
                                    helpers.addResult(results, 0, 'Dynamic data masking is enabled for SQL database', location, database.id);
                                } else {
                                    helpers.addResult(results, 2, 'Dynamic data masking is not enabled for SQL database', location, database.id);
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


