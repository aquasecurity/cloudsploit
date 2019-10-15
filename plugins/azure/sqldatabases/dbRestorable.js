const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'DB Restorable',
    category: 'SQL Databases',
    description: 'Ensures SQL Database instances can be restored to a recent point',
    more_info: 'Automated backups of SQL databases with recent restore points help ensure that database recovery operations can occur without significant data loss.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-recovery-using-backups',
    recommended_action: 'Ensure that each SQL database has automated backups configured with a sufficient retention period and that the last known backup operation completes successfully.',
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
                    'Unable to query for SQL Databases: ' + helpers.addError(databases), location);
                return rcb();
            }

            if (!databases.data.length) {
                helpers.addResult(results, 0, 'No SQL databases found', location);
                return rcb();
            }

            databases.data.forEach(function(database){
                if (!database.earliestRestoreDate) {
                    helpers.addResult(results, 2, 
                        'SQL Database is not restorable', location, database.id);
                } else {
                    helpers.addResult(results, 0, 
                        'SQL Database is restorable', location, database.id);
                }
            });

        rcb();
        }, function () {
        // Global checking goes here
            callback(null, results, source);
        });
    }
};
