var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'MySQL Skip Show Database Enabled',
    category: 'SQL',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures SQL instances for MySQL type have skip show database flag enabled.',
    more_info: 'SQL instances for MySQL type database provides skip_show_database flag, revents people from using the SHOW DATABASES statement if they do not have the SHOW DATABASES privilege. This can improve security if you have concerns about users being able to see databases belonging to other users.',
    link: 'https://cloud.google.com/sql/docs/mysql/flags',
    recommended_action: 'Ensure that skip show database flag is enabled for all MySQL instances.',
    apis: ['sql:list'],
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

        async.each(regions.sql, function(region, rcb){
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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toLowerCase().includes('mysql')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of MySQL type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags &&
                    sqlInstance.settings.databaseFlags.length) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'skip_show_database' &&
                        flag.value && flag.value == 'on');
                        
                    if (found) {
                        helpers.addResult(results, 0, 
                            'SQL instance has skip_show_database flag enabled', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'SQL instance does not have skip_show_database flag enabled', region, resource);

                    }
                } else {
                    helpers.addResult(results, 2,
                        'SQL instance does not have skip_show_database flag enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
