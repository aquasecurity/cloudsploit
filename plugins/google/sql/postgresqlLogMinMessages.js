var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Log Min Messages',
    category: 'SQL',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures SQL instances for PostgreSQL type have log min messages flag set to Warning or stricter.',
    more_info: 'SQL instance for PostgreSQL databases provides log_min_messages flag. It is used to define the minimum message severity level that is considered as an error statement.',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log_min_messages flag is set to at least Warning for all PostgreSQL instances.',
    apis: ['sql:list'],
    settings: {
        log_min_messages: {
            name: 'Log Min Messages',
            description: 'Return a passing result if the flag value is used from the setting list.',
            regex: '^(error|log|fatal|panic)$',
            default: 'warning'
        }
    },
    realtime_triggers:['cloudsql.instances.delete','cloudsql.instances.create','cloudsql.instances.update'],

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

        const LOG_LEVELS = ['warning', 'error', 'log', 'fatal', 'panic'];

        var log_min_messages = settings.log_min_messages || this.settings.log_min_messages.default;
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
                log_min_messages =  log_min_messages.toLowerCase();
                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'log_min_messages' &&
                        flag.value);
                    if (found) {
                        let currentLevel = LOG_LEVELS.indexOf(found.value.toLowerCase());
                        let expectedLevel = LOG_LEVELS.indexOf(log_min_messages);

                        if (currentLevel >= expectedLevel) {
                            helpers.addResult(results, 0,
                                `SQL instance has log_min_messages flag set to "${found.value}" which is greater than or equal to "${log_min_messages}"`, region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `SQL instance has log_min_messages flag set to "${found.value}" which is less than "${log_min_messages}"`, region, resource);
                        }
                    } 
                } 

                if (!found) {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have log_min_messages flag set to at least Warning', region, resource);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}; 