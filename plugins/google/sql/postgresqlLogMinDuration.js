var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Min Duration Statement',
    category: 'SQL',
    description: 'Ensures SQL instances for PostgreSQL type have log min duration statement flag disabled.',
    more_info: 'SQL instance for PostgreSQL databases provides log_min_duration_statement flag. It is used to log the duration of every completed statement. This should always be disabled as there can be sensitive information as well that should not be recorded in the logs.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log_min_duration_statement flag is disabled for all PostgreSQL instances.',
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
                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('postgres')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of PostgreSQL type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_min_duration_statement' &&
                                                                        flag.value && flag.value == '-1');

                        if (found) {
                            helpers.addResult(results, 0, 
                                'SQL instance does not have log_min_duration_statement flag enabled', region, sqlInstance.name);
                        } else {
                            helpers.addResult(results, 2,
                                'SQL instance have log_min_duration_statement flag enabled', region, sqlInstance.name);
                        }
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE") {
                } else {
                    helpers.addResult(results, 0, 
                        'SQL instance does not have log_min_duration_statement flag enabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
