var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Secure Enclaves Encryption Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure secure enclaves encryption is enabled for SQL databases.',
    more_info: 'Secure enclaves encryption protects the data by encrypting it on the client side and never allowing the data or the corresponding cryptographic keys to appear in plaintext inside the Database Engine. As a result, the functionality on encrypted columns inside the database is severely restricted.',
    recommended_action: 'Enable secure enclaves encryption for all SQL databases.',
    link: 'https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-enclaves?view=sql-server-ver16',
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
                        databases.data.forEach(database => {
                            if (!database.preferredEnclaveType) {
                                helpers.addResult(results, 2, 'Secure enclaves encryption is disabled for SQL database', location, database.id);
                            } else {
                                helpers.addResult(results, 0, 'Secure enclaves encryption is enabled for SQL database', location, database.id);
                            }
                        }
                        );
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
