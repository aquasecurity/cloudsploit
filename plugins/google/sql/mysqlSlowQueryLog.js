var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'MySQL Slow Query Log Enabled',
    category: 'SQL',
    description: 'Ensures SQL instances for MySQL type have slow query log flag enabled.',
    more_info: 'SQL instances for MySQL type database which helps finding inefficient or time-consuming SQL queries for your MySQL databases.',
    link: 'https://cloud.google.com/sql/docs/mysql/flags',
    recommended_action: 'Ensure that slow query log flag is enabled for all MySQL instances.',
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
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() == 'READ_REPLICA_INSTANCE') return;

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('mysql')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of MySQL type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'slow_query_log' &&
                                                                        flag.value && flag.value == 'on');

                        if (found) {
                            helpers.addResult(results, 0, 
                                'SQL instance has slow query log flag enabled', region, sqlInstance.name);
                        } else {
                            helpers.addResult(results, 2,
                                'SQL instance has slow query log flag disabled', region, sqlInstance.name);
                        }
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance has slow query log flag disabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
