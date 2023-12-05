var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Secure Enclaves Encryption Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensure Always Encrypted with secure enclaves is enabled at the database level.',
    more_info: 'Always Encrypted with secure enclaves allows encrypted data to be processed inside a secure enclave for improved security. These properties make the secure enclave a trusted execution environment that can safely access cryptographic keys and sensitive data in plaintext, without compromising data confidentiality.',
    recommended_action: 'Enable Always Encrypted with secure enclaves for the SQL database.',
    link: 'https://learn.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-enclaves?view=sql-server-ver16',
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
                        databases.data.forEach(database=> {

                            if (!database.preferredEnclaveType) {
                                helpers.addResult(results, 2, 'Always Encrypted with secure enclaves is disabled for SQL database', location, database.id);
                            } else {
                                helpers.addResult(results, 0, 'Always Encrypted with secure enclaves is enabled for SQL database', location, database.id);
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
