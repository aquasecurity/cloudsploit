var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Always Encrypted with Secure Enclaves for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Enable Always Encrypted with secure enclaves at the database level for enhanced data security.',
    more_info: 'Always Encrypted with secure enclaves allows encrypted data to be processed inside a secure enclave for improved security.',
    recommended_action: 'Enable Always Encrypted with secure enclaves for the SQL database to enhance data security.',
    link: 'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/always-encrypted-enclaves-security-features?view=sql-server-ver15',
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

                            if (!database.preferredEnclaveType) {
                                helpers.addResult(results, 2, 'Always Encrypted with secure enclaves disabled', location, database.id);
                            } else {
                                helpers.addResult(results, 0, 'Always Encrypted with secure enclaves enabled', location, database.id);
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
