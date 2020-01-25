const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'TDE Protector Encrypted',
    category: 'SQL Server',
    description: 'Ensures SQL Server TDE protector is encrypted with BYOK (Bring Your Own Key)',
    more_info: 'Enabling BYOK in the TDE protector allows for greater control and transparency, as well as increasing security by having full control of the encryption keys.',
    recommended_action: 'Ensure that a BYOK key is set for the Transparent Data Encryption of each SQL Server.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/transparent-data-encryption-byok-azure-sql',
    apis: ['servers:sql:list', 'resourceGroups:list', 'encryptionProtectors:get'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.encryptionProtectors, (location, rcb) => {

            const encryptionProtectors = helpers.addSource(cache, source,
                ['encryptionProtectors', 'get', location]);

            if (!encryptionProtectors) return rcb();

            if (encryptionProtectors.err || !encryptionProtectors.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL Server Encryption Protectors: ' + helpers.addError(encryptionProtectors), location);
                return rcb();
            }

            if (!encryptionProtectors.data.length) {
                helpers.addResult(results, 0, 'No existing SQL Servers found', location);
                return rcb();
            }

            for (let res in encryptionProtectors.data) {
                const encryptionProtector = encryptionProtectors.data[res];

                if ((encryptionProtector.kind &&
                    encryptionProtector.kind != 'azurekeyvault') ||
                    (encryptionProtector.serverKeyType ||
                    encryptionProtector.serverKeyType != 'AzureKeyVault') ||
                    !encryptionProtector.uri) {

                    helpers.addResult(results, 2,
                        'SQL Server TDE protector is not encrypted with BYOK', location, encryptionProtector.id);
                } else {
                    helpers.addResult(results, 0,
                        'SQL Server TDE protector is encrypted with BYOK', location, encryptionProtector.id);
                }
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
