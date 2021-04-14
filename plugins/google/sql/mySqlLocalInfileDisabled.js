var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'MySQL local infile disabled',
    category: 'SQL',
    description: 'Ensures SQL instances for MySQL type does not have local infile flag enabled.',
    more_info: 'Ensures MySQL db does not have local infile flag enabled, it control the load data statements for database. For security reasons it should be disabled.',
    link: 'https://cloud.google.com/sql/docs/mysql/flags',
    recommended_action: 'Ensure that local infile flag is disabled for all MySQL instances.',
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
                if (!sqlInstance.databaseVersion.toLowerCase().includes('mysql')) {
                    helpers.addResult(results, 0, 
                        'No SQL instance found with mySQL type', region, sqlInstance.name);
                    return;
                }
                if (!sqlInstance.settings.databaseFlags.length) {
                    helpers.addResult(results, 0, 
                        'SQL instance does not have any flag', region, sqlInstance.name);
                    return;
                }
                flags = sqlInstance.settings.databaseFlags
                flags.forEach(flag => {
                    if(!(flag.name == 'local_infile')) {
                        helpers.addResult(results, 0, 
                            'SQL instance does not have local_infile flag', region, sqlInstance.name);
                        return;
                    }
                    
                    if(flag.value == 'off') {
                        helpers.addResult(results, 0, 
                            'SQL instance have local_infile flag disabled', region, sqlInstance.name);
                    }
                    else {
                        helpers.addResult(results, 2, 
                            'SQL instance have local_infile flag enabled', region, sqlInstance.name);
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