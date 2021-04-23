var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Min Error Statement',
    category: 'SQL',
    description: 'Ensures SQL instances for PostgreSQL type have log min error statement flag set to Error.',
    more_info: 'SQL instance for PostgreSQL databases provides log_min_error_statement flag. It is used to mention/tag that the error messages. Setting it to Error value will help to find the error messages appropriately.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log_min_error_statement flag is set to Error for all PostgreSQL instances.',
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
                        let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_min_error_statement' &&
                                                                        flag.value && flag.value == 'ERROR');

                        if (found) {
                            helpers.addResult(results, 0, 
                                'SQL instance have log_min_error_statement flag set to Error', region, sqlInstance.name);
                        } else {
                            helpers.addResult(results, 2,
                                'SQL instance does not have log_min_error_statement flag set to Error', region, sqlInstance.name);
                        }
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE") {
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have log_min_error_statement flag set to Error', region, sqlInstance.name);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
} 