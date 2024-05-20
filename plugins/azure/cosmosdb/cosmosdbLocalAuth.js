const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Local Authentication Disabled',
    category: 'Cosmos DB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that local authentication is disabled for Cosmos DB accounts.',
    more_info: 'For enhanced security, centralized identity management and seamless integration with Azure\'s authentication and authorization services, it is recommended to rely on Azure Active Directory (Azure AD) and disable local authentication for Azure Cosmos DB accounts.',
    recommended_action: 'Ensure that Cosmos DB accounts have local authentication disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-setup-rbac#disable-local-auth',
    apis: ['databaseAccounts:list'],
    realtime_triggers: ['microsoftdocumentdb:databaseaccounts:write','microsoftdocumentdb:databaseaccounts:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databaseAccounts, (location, rcb) => {
            const databaseAccounts = helpers.addSource(cache, source, 
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

            for (let dbAccount of databaseAccounts.data) {
                if (!dbAccount.id) continue;

                if (dbAccount.disableLocalAuth) {
                    helpers.addResult(results, 0, 'Cosmos DB account has local authentication disabled', location, dbAccount.id);
                } else {
                    helpers.addResult(results, 2, 'Cosmos DB account has local authentication enabled', location, dbAccount.id);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};