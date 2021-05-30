var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Cross DB Ownership Chaining',
    category: 'SQL',
    description: 'Ensures SQL database instances of SQL Server type have cross db ownership chaining flag disabled.',
    more_info: 'SQL databases of SQL Server provide cross DB ownership chaining flag. It is used to configure cross-database ownership chaining ' +
        'for all databases. It is enabled by default and should be disabled for security unless all required.',
    link: 'https://cloud.google.com/sql/docs/sqlserver/flags',
    recommended_action: 'Ensure that cross DB ownership chaining flag is disabled for all SQLServer instances.',
    apis: ['instances:sql:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb) {
            let sqlInstances = helpers.addSource(
                cache, source, ['instances', 'sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() == 'READ_REPLICA_INSTANCE') return;

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('sqlserver')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of SQL Server type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name &&
                        flag.name == 'cross db ownership chaining' && flag.value && flag.value == 'off');

                    if (found) {
                        helpers.addResult(results, 0, 
                            'SQL instance has cross DB ownership chaining flag disabled', region, sqlInstance.name);
                    } else {
                        helpers.addResult(results, 2,
                            'SQL instance has cross DB ownership chaining flag enabled', region, sqlInstance.name);
                    }
                } else {
                    helpers.addResult(results, 0, 
                        'SQL instance does not have any flags', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
