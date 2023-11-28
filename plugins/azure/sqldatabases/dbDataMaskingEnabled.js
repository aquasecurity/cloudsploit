var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Set Dynamic Data Masking for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Set up dynamic data masking to protect sensitive data exposure in SQL databases.',
    more_info: 'Dynamic data masking helps prevent unauthorized access to sensitive data by hiding it in query results.',
    recommended_action: 'Set up dynamic data masking for designated database fields to enhance data security.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-dynamic-data-masking-get-started-portal',
    apis: ['servers:listSql', 'databases:listByServer', 'dataMaskingPolicies:get'],
    
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
                        databases.data.forEach(function(database) {
                            
                            var dataMaskingPolicies = helpers.addSource(cache, source, ['dataMaskingPolicies', 'get', location, database.id]);
                            if (!dataMaskingPolicies || dataMaskingPolicies.err || !dataMaskingPolicies.data) {
                                helpers.addResult(results, 3, 'Unable to query dynamic data masking: ' + helpers.addError(dataMaskingPolicies), location, database.id);
                            } else {
                                if (dataMaskingPolicies.data.dataMaskingState.toLowerCase()=='enabled') {
                                    helpers.addResult(results, 0, 'Dynamic data masking is enabled for the database', location, database.id);
                                } else {
                                    helpers.addResult(results, 2, 'Dynamic data masking is not enabled for the database', location, database.id);
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


