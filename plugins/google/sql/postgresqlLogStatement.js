var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Statement',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensures SQL instances for PostgreSQL type have log statement flag set to desired value.',
    more_info: 'SQL instance for PostgreSQL databases provides log_statement flag which can be set to align with your organization security and logging policies facilitates later auditing and review of database activities. Not having it set to the appropriate value can cause too many or too few statements to be logged.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log_statement flag is set to desired value.',
    apis: ['sql:list'],
    settings: {
        log_statement: {
            name: 'Log Statement',
            description: 'Return a passing result if the flag value is used from the setting list.',
            regex: '^(ddl|mod|all)$',
            default: 'ddl'
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

        var log_statement = settings.log_statement || this.settings.log_statement.default;
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
                log_statement =  log_statement.toLowerCase();
                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_statement' &&
                        flag.value);
                    if (found) {
                        if (found.value == log_statement) {
                            helpers.addResult(results, 0,
                                `SQL instance has log_statement flag set to "${found.value}"`, region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `SQL instance has log_statement flag set to "${found.value}" instead of "${log_statement}"`, region, resource);
                        }
                    }
                }

                if (!found) {
                    helpers.addResult(results, 2,
                        `SQL instance does not have log_statement flag set to "${log_statement}"`, region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 
