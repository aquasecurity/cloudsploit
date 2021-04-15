var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL log_lock_waits flag enabled',
    category: 'SQL',
    description: 'Ensures SQL instances for PostgreSQL type have log_lock_waits flag enabled.',
    more_info: 'Ensures PostgreSQL databases to have log_lock_waits flag enabled as it is not enabled by default. Enabling it will make sure that log messages are generated whenever a session waits longer than deadlock_timeout to acquire a lock.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags#config',
    recommended_action: 'Ensure that log_lock_waits flag is enabled for all PostgreSQL instances.',
    apis: ['instances:sql:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb){
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
                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('postgres')) {
                    helpers.addResult(results, 0, 
                        'No SQL instance found with postgreSQL type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        flags = sqlInstance.settings.databaseFlags
                        flag_enabled = false
                        flags.forEach(flag => {
                            if(flag.name == 'log_lock_waits' && flag.value == 'on') {
                                flag_enabled = true
                            }
                        })
                        if(flag_enabled == true) {
                            helpers.addResult(results, 0, 
                                'SQL instance have log_lock_waits flag enabled', region, sqlInstance.name);
                            return;
                        }else {
                            helpers.addResult(results, 2,
                                'SQL instance does not have log_lock_waits flag enabled', region, sqlInstance.name);
                        }
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE"){
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have log_lock_waits flag enabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}