const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'DB Restorable',
    category: 'SQL Databases',
    description: 'Ensures SQL Database instances can be restored to a recent point',  
    more_info: 'Azure by default does not enable Geo Replication. Enable Geo-replication to have restoration points.',
    link: 'https://azure.microsoft.com/en-us/blog/azure-sql-database-now-offers-zone-redundant-premium-databases-and-elastic-pools/',
    recommended_action: '1. Enter SQL Databases. 2. Select the Database. 3. Select the Geo-Replication. 4. Select the location in which to enable Replication.',
    apis: ['resourceGroups:list', 'servers:sql:list', 'databases:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databases, function (location, rcb) {
            const databases = helpers.addSource(cache, source,
                ['databases', 'listByServer', location]);

            if (!databases) return rcb();

            if (databases.err || !databases.data) {
                helpers.addResult(results, 3,
                    'Unable to query Databases: ' + helpers.addError(databases), location);
                return rcb();
            }

            if (!databases.data.length) {
                helpers.addResult(results, 0, 'No Databases found', location);
                return rcb();
            };

            databases.data.forEach(function(database){
                if (!database.earliestRestoreDate) {
                    helpers.addResult(results, 2, 
                        'SQL Database is not restorable', location, database.id);
                } else {
                    helpers.addResult(results, 0, 
                        'SQL Database is restorable', location, database.id);
                };
            });

        rcb();
        }, function () {
        // Global checking goes here
            callback(null, results, source);
        });
    }
};
