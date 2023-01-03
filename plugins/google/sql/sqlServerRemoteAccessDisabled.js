var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Server Remote Access Flag Disabled',
    category: 'SQL',
    domain: 'Databases',
    description: 'Ensure that remote access flag is disabled for SQL Server instances.',
    more_info: ' The Remote Access option controls the execution of local stored procedures on remote servers or remote stored procedures on local server. Remote access functionality can be abused to launch a Denial-of-Service (DoS) attack on remote servers by off-loading query processing to a target, hence this should be disabled.',
    link: 'https://cloud.google.com/sql/docs/sqlserver/flags',
    recommended_action: 'Ensure that all SQL Server database instances have remote access flag set to disabled.',
    apis: ['sql:list'],

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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toUpperCase().startsWith('SQLSERVER')) {
                    helpers.addResult(results, 0, 'SQL instance database type is not of SQL Server type', region, resource);
                    return;
                }

                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'remote access' &&
                        flag.value && flag.value == 'on');
                    if (found) {
                        helpers.addResult(results, 2,
                            'SQL instance has "remote access" flag enabled', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'SQL instance does not have "remote access" flag enabled', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0,
                        'SQL instance does not have "remote access" flag enabled', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
