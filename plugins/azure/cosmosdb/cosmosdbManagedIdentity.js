const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Managed Identity',
    category: 'Cosmos DB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that Microsoft Azure Cosmos DB accounts has managed identity enabled.',
    more_info: 'Enabling managed identity for Azure Cosmos DB accounts automates credential management, enhancing security by avoiding hard-coded credentials and simplifying access control to Azure services.',
    link: 'https://learn.microsoft.com/en-us/azure/cosmos-db/managed-identity-based-authentication',
    recommended_action: 'Enable system or user-assigned identities for all Azure Cosmos DB accounts.',
    apis: ['databaseAccounts:list'],
    realtime_triggers: ['microsoftdocumentdb:databaseaccounts:write','microsoftdocumentdb:databaseaccounts:write'],
    
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databaseAccounts, function(location, rcb) {
            var databaseAccounts = helpers.addSource(cache, source,
                ['databaseAccounts', 'list', location]);

            if (!databaseAccounts) return rcb();

            if (databaseAccounts.err || !databaseAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Cosmos DB accounts: ' + helpers.addError(databaseAccounts), location);
                return rcb();
            }

            if (!databaseAccounts.data.length) {
                helpers.addResult(results, 0, 'No Cosmos DB accounts found', location);
                return rcb();
            }

            databaseAccounts.data.forEach(account => {
                if (!account.id) return;

                if (account.identity && account.identity.type &&  
                    (account.identity.type.toLowerCase() === 'systemassigned' || account.identity.type.toLowerCase() === 'userassigned')) {
                    helpers.addResult(results, 0,
                        'Cosmos DB account has managed identity enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'Cosmos DB account does not have managed identity enabled', location, account.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
