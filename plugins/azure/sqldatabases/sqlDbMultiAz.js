const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL DB Multiple AZ',
    category: 'SQL Databases',
    description: 'Ensures that SQL DB instances are created to be cross-AZ for high availability.',
    more_info: 'Creating SQL DB instances in a single AZ creates a single point of failure for all systems relying on that database. All SQL DB instances should be created in multiple AZs to ensure proper failover.',
    link: 'https://azure.microsoft.com/en-us/blog/azure-sql-database-now-offers-zone-redundant-premium-databases-and-elastic-pools/',
    recommended_action: '1. Enter SQL Databases. 2. Select the Database. 3. Select the configure blade. 4. Choose the premium tab and enable database zone redundant at the bottom.',
    apis: ['resourceGroups:list', 'servers:sql:list', 'databases:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.databases, function (location, rcb) {
            const databases = helpers.addSource(cache, source,
                ['databases', 'listByServer', location]);

            if(!databases) return rcb();

            if (databases.err || !databases.data) {
                helpers.addResult(results, 3,
                'Unable to query Databases: ' + helpers.addError(databases), location);
                return rcb();
            };

            if (!databases.data.length) {
                helpers.addResult(results, 0, 'No Databases found', location);
                return rcb();
            };

            databases.data.forEach(database => {
                if (!database.zoneRedundant) {
                helpers.addResult(results, 2, 
                    'SQL Database does not have multi-AZ enabled', location, database.id);
                } else {
                helpers.addResult(results, 0, 
                    'SQL Database has multi-AZ enabled', location, database.id);
                };
            });

            rcb();
        }, function () {
        // Global checking goes here
            callback(null, results, source);
        });
    }
};