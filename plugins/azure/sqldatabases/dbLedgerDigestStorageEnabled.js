var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Ledger Digest Storage Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensure that ledger automatic digest storage is enabled.',
    more_info: 'Configuring automatic Ledger digest storage allows for the generation and storage of digests for later verification.',
    recommended_action: 'Configure an Azure Storage account or Azure Confidential Ledger for automatic Ledger digest storage. ',
    link: 'https://learn.microsoft.com/en-us/sql/relational-databases/security/ledger/ledger-overview?view=sql-server-ver16',
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
                        databases.data.forEach(database => {
                            var ledgerDigestUploads = helpers.addSource(cache, source, ['ledgerDigestUploads', 'list', location, database.id]);
                            if (!ledgerDigestUploads || ledgerDigestUploads.err || !ledgerDigestUploads.data) {
                                helpers.addResult(results, 3, 'Unable to query for Ledger Digest Uploads for SQL database: ' + helpers.addError(ledgerDigestUploads), location, database.id);
                            } else {
                                if (ledgerDigestUploads.data.length && ledgerDigestUploads.data[0].state.toLowerCase() == 'enabled') {
                                    helpers.addResult(results, 0, 'Ledger automatic digest storage is enabled for SQL database', location, database.id);
                                } else {
                                    helpers.addResult(results, 2, 'Ledger automatic digest storage is not enabled for SQL database', location, database.id);
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
