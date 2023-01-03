const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Has Tags',
    category: 'Cosmos DB',
    domain: 'Databases',
    description: 'Ensure that Azure Cosmos DB database accounts have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    recommended_action: 'Modify affected database accounts and add tags.',
    apis: ['databaseAccounts:list'],

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

            for (let db of databaseAccounts.data) {
                if (!db.id) continue;

                if (db.tags && Object.entries(db.tags).length > 0){
                    helpers.addResult(results, 0, 'Cosmos DB account has tags associated', location, db.id);
                } else {
                    helpers.addResult(results, 2, 'Cosmos DB account does not have tags associated', location, db.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
