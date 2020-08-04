const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'TDE Protector Encrypted',
    category: 'SQL Server',
    description: 'Ensures SQL Server TDE protector is encrypted with BYOK (Bring Your Own Key)',
    more_info: 'Enabling BYOK in the TDE protector allows for greater control and transparency, as well as increasing security by having full control of the encryption keys.',
    recommended_action: 'Ensure that a BYOK key is set for the Transparent Data Encryption of each SQL Server.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/transparent-data-encryption-byok-azure-sql',
    apis: ['servers:listSql', 'encryptionProtectors:listByServer'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const encryptionProtectors = helpers.addSource(cache, source,
                    ['encryptionProtectors', 'listByServer', location, server.id]);

                if (!encryptionProtectors || encryptionProtectors.err || !encryptionProtectors.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL Server Encryption Protectors: ' + helpers.addError(encryptionProtectors), location, server.id);
                } else {
                    if (!encryptionProtectors.data.length) {
                        helpers.addResult(results, 0, 'No SQL Server Encryption Protectors found for server', location, server.id);
                    } else {
                        encryptionProtectors.data.forEach(encryptionProtector => {
                            if ((encryptionProtector.kind &&
                                encryptionProtector.kind.toLowerCase() != 'azurekeyvault') ||
                                (encryptionProtector.serverKeyType ||
                                    encryptionProtector.serverKeyType.toLowerCase() != 'azurekeyvault') ||
                                !encryptionProtector.uri) {
                                helpers.addResult(results, 2,
                                    'SQL Server TDE protector is not encrypted with BYOK', location, encryptionProtector.id);
                            } else {
                                helpers.addResult(results, 0,
                                    'SQL Server TDE protector is encrypted with BYOK', location, encryptionProtector.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
