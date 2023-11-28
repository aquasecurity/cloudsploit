var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Azure Ledger for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Enable Azure ledger to protect the integrity of data for SQL databases.',
    more_info: 'Azure ledger helps protect the integrity of data by enabling customers to use cryptographic seals on their data.',
    recommended_action: 'Enable Azure ledger for all future tables in the SQL database to enhance data integrity.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-ledger-overview',
    apis: ['servers:listSql', 'databases:listByServer'],
    
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
                        // Loop through databases
                        databases.data.forEach(function(database) {
                          
                            if (database.isLedgerOn==true) {
                                helpers.addResult(results, 0, 'Azure ledger is enabled', location, database.id);
                            } else {
                                helpers.addResult(results, 2, 'Azure ledger is disabled', location, database.id);
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
