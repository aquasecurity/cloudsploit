var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Transparent Data Encryption Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensure Transparent Data Encryption (TDE) is enabled on SQL databases for enhanced security',
    more_info: 'TDE helps protect sensitive data at rest by encrypting the database files.',
    recommended_action: 'Enable TDE for SQL databases to enhance data security.',
    link: 'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption?view=sql-server-ver15',
    apis: ['servers:listSql','databases:listByServer','transparentDataEncryption:list'],
    
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
                            
                            var transparentDataEncryption = helpers.addSource(cache, source, ['transparentDataEncryption', 'list', location, database.id]);
                            
                            if (!transparentDataEncryption || transparentDataEncryption.err || !transparentDataEncryption.data || !transparentDataEncryption.data.length) {
                                helpers.addResult(results, 3, 'Unable to query transparent data encryption for SQL Database: ' + helpers.addError(transparentDataEncryption), location, database.id);
                                return;
                            }

                            if (transparentDataEncryption.data[0].state.toLowerCase()=='enabled') {
                                helpers.addResult(results, 0, 'Transparent data encryption is enabled for SQL Database', location, database.id);
                            } else {
                                helpers.addResult(results, 2, 'Transparent data encryption is Disabled for SQL Database', location, database.id);
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
