var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQLServer Cross Db Ownership Chaining',
    category: 'SQL',
    description: 'Ensures SQL instances for SQLServer type have cross db ownership chaining flag disabled.',
    more_info: 'SQL instance for SQLServer databases provides cross DB ownership chaining flag. It is used to configure cross-database ownership chaining for all databases. It is enabled by default and should be disabled for security unless all databases agree for this setting.',
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
                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('sqlserver')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of SQLServer type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'cross db ownership chaining' &&
                                                                        flag.value && flag.value == 'off');

                        if (found) {
                            helpers.addResult(results, 0, 
                                'SQL instance does not have cross db ownership chaining flag enabled', region, sqlInstance.name);
                        } else {
                            helpers.addResult(results, 2,
                                'SQL instance has cross DB ownership chaining flag enabled', region, sqlInstance.name);
                        }
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE") {
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance have cross db ownership chaining flag enabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
