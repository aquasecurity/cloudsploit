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
                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('mysql')) {
                    helpers.addResult(results, 0, 
                        'No SQL instance found with MySQL type', region, sqlInstance.name);
                    return;
                }

                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                        flags = sqlInstance.settings.databaseFlags
                        flag_disabled = false
                        flags.forEach(flag => {
                            if(flag.name == 'local_infile' && flag.value == 'off') {
                                flag_disabled = true
                            }
                        })
                        if(flag_disabled == true) {
                            helpers.addResult(results, 0, 
                                'SQL instance does not have local_infile flag enabled', region, sqlInstance.name);
                            return;
                        }else {
                            helpers.addResult(results, 2,
                                'SQL instance have local_infile flag enabled', region, sqlInstance.name);
                        }
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE"){
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance have local_infile flag enabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}