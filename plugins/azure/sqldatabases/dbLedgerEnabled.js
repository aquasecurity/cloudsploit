var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Ledger Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure ledger is enabled for SQL databases.',
    more_info: 'Azure ledger helps protect the integrity of data by enabling customers to use cryptographic seals on their data. The database ledger incrementally captures the state of a database as the database evolves over time, while updates occur on ledger tables',
    recommended_action: 'Enable Azure ledger for all SQL databases.',
    link: 'https://learn.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-overview?view=sql-server-ver16',
    apis: ['servers:listSql', 'databases:listByServer'],
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
            servers.data.forEach(server=> {
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
                        databases.data.forEach(database => {
                          
                            if (database.isLedgerOn) {
                                helpers.addResult(results, 0, 'Ledger is enabled for SQL database', location, database.id);
                            } else {
                                helpers.addResult(results, 2, 'Ledger is not enabled for SQL database', location, database.id);
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
