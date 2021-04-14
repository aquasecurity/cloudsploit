var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL log connections flag enabled',
    category: 'SQL',
    description: 'Ensures SQL instances for PostgreSQL type have log connections flag enabled.',
    more_info: 'Ensures PostgreSQL databases to have log connections flag enabled as it is not enabled by default. Enabling it will make sure to log all connection tries',
    link: 'https://cloud.google.com/sql/docs/postgres/flags',
    recommended_action: 'Ensure that log connections flag is enabled for all PostgreSQL instances.',
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
                if (!sqlInstance.databaseVersion.toLowerCase().includes('postgres')) {
                    helpers.addResult(results, 0, 
                        'No SQL instance found with postgreSQL type', region, sqlInstance.name);
                    return;
                }
                if (!sqlInstance.settings.databaseFlags.length) {
                    helpers.addResult(results, 0, 
                        'SQL instance does not have any flag', region, sqlInstance.name);
                    return;
                }
                flags = sqlInstance.settings.databaseFlags
                flags.forEach(flag => {
                    if(!(flag.name == 'log_connections')) {
                        helpers.addResult(results, 0, 
                            'SQL instance does not have log_connections flag', region, sqlInstance.name);
                        return;
                    }
                    
                    if(flag.value == 'on') {
                        helpers.addResult(results, 0, 
                            'SQL instance have log_connections flag enabled', region, sqlInstance.name);
                    }
                    else {
                        helpers.addResult(results, 2, 
                            'SQL instance have log_connections flag disabled', region, sqlInstance.name);
                    }
                })
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}