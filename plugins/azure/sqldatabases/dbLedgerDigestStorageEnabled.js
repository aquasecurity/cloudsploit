var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Automatic Ledger Digest Storage for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Enable automatic Ledger digest storage for enhanced data integrity.',
    more_info: 'Configuring automatic Ledger digest storage allows for the generation and storage of digests for later verification.',
    recommended_action: 'Configure an Azure Storage account or Azure Confidential Ledger for automatic Ledger digest storage. Alternatively, manually generate digests and store them in a secure location.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-ledger-overview',
    apis: ['servers:listSql', 'databases:listByServer', 'ledgerDigestUploads:list'],
    
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
                            var ledgerDigestUploads = helpers.addSource(cache, source, ['ledgerDigestUploads', 'list', location, database.id]);
                            if (!ledgerDigestUploads || ledgerDigestUploads.err) {
                                helpers.addResult(results, 3, 'Unable to query for Azure ledger: ' + helpers.addError(ledgerDigestUploads), location, database.id);
                            } else {
                                if (ledgerDigestUploads.data[0].state.toLowerCase() == 'enabled') {
                                    helpers.addResult(results, 0, 'Automatic Ledger digest storage is enabled', location, database.id);
                                } else {
                                    helpers.addResult(results, 2, 'Automatic Ledger digest storage is disbaled', location, database.id);
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
