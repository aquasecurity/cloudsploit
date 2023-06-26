var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Error Verbosity',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure SQL instances for PostgreSQL type have log error verbosity flag set to default or stricter.',
    more_info: 'SQL instance for PostgreSQL databases provides log_error_verbosity flag to control the verbosity/details of the messages logged. if this flag is not set correctly too many or too few statements can be logged which can cause problems while troubleshooting.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log_error_verbosity flag is set to at least default for all PostgreSQL instances.',
    apis: ['sql:list'],
    settings: {
        log_error_verbosity: {
            name: 'Log Error verbosity',
            description: 'Return a passing result if the flag value is used from the setting list.',
            regex: '^(default|verbose)$',
            default: 'default'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let project = projects.data[0].name;

        const LOG_LEVELS = ['default', 'verbose'];

        var log_error_verbosity = settings.log_error_verbosity || this.settings.log_error_verbosity.default;
        async.each(regions.sql, function(region, rcb) {
            let sqlInstances = helpers.addSource(
                cache, source, ['sql', 'list', region]);

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
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === 'READ_REPLICA_INSTANCE') return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('postgres')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of PostgreSQL type', region, resource);
                    return;
                }
                let found; 
                log_error_verbosity = log_error_verbosity.toLowerCase();
                let currentLevelValue = 'default';
                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_error_verbosity' &&
                        flag.value);
                }
                if (found) {
                    currentLevelValue = found.value;
                }
                let currentLevel = LOG_LEVELS.indexOf(currentLevelValue.toLowerCase());
                let expectedLevel = LOG_LEVELS.indexOf(log_error_verbosity);

                if (currentLevel >= expectedLevel) {
                    helpers.addResult(results, 0,
                        `SQL instance has log_error_verbosity flag set to "${currentLevelValue}" which is greater than or equal to "${log_error_verbosity}"`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `SQL instance has log_error_verbosity flag set to "${currentLevelValue}" which is less than "${log_error_verbosity}"`, region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 