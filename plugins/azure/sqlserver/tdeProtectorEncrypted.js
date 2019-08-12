const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'TDE Protector Encrypted',
    category: 'SQL Server',
    description: 'Ensure SQL server TDE protector is encrypted with BYOK (Use your own key)',
    more_info: 'Enabling BYOK in the TDE protector allows for greater control and transparency, as well as increasing security by having full control of the encryption keys.',
    recommended_action: '1. Enter the SQL Server category in the Azure portal. 2. Choose the sql server. 3. Enter the Transparent Data Encryption blade. 4. Enable Use Your Own Key. 5. Select an existing key or create one.',
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
                    'Unable to query SQL Server Encryption Protectors: ' + helpers.addError(encryptionProtectors), location);
                return rcb();
            }

            if (!encryptionProtectors.data.length) {
                helpers.addResult(results, 0, 'No existing SQL Server', location);
                return rcb();
            }

            let allProtected = true;

            for (let res in encryptionProtectors.data) {
                const encryptionProtector = encryptionProtectors.data[res];

                if ((encryptionProtector.kind &&
                    encryptionProtector.kind != 'azurekeyvault') ||
                    (encryptionProtector.serverKeyType ||
                    encryptionProtector.serverKeyType != 'AzureKeyVault') ||
                    !encryptionProtector.uri) {

                    helpers.addResult(results, 1,
                        'SQL servers TDE protector is not encrypted with BYOK', location, encryptionProtector.id);
                    allProtected = false;
                }
            }

            if (allProtected) {
                helpers.addResult(results, 0,
                    'All SQL servers TDE protectors are encrypted with BYOK', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
