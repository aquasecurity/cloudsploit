const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL DB Multiple AZ',
    category: 'SQL Databases',
    description: 'Ensures that SQL Database instances are created to be cross-AZ for high availability',
    more_info: 'Creating SQL Database instances in a single availability zone creates a single point of failure for all systems relying on that database. All SQL Database instances should be created in multiple availability zones to ensure proper failover.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-high-availability#zone-redundant-configuration',
    recommended_action: 'Ensure that each SQL Database is configured to be zone redundant.',
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
                'Unable to query for SQL Databases: ' + helpers.addError(databases), location);
                return rcb();
            }

            if (!databases.data.length) {
                helpers.addResult(results, 0, 'No SQL Databases found', location);
                return rcb();
            }

            databases.data.forEach(database => {
                if (!database.zoneRedundant) {
                    helpers.addResult(results, 2, 
                        'SQL Database does not have zone redundancy enabled', location, database.id);
                } else {
                    helpers.addResult(results, 0, 
                        'SQL Database has zone redundancy enabled', location, database.id);
                }
            });

            rcb();
        }, function () {
        // Global checking goes here
            callback(null, results, source);
        });
    }
};