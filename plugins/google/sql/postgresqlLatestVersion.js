var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'PostgreSQL Latest Version',
    category: 'SQL',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that PostgreSQL database servers are using the latest major version of PostgreSQL database.',
    more_info: 'To make use of the latest database features and benefit from enhanced performance and security, make sure that your PostgreSQL database instances are using the latest major version of PostgreSQL.',
    link: 'https://cloud.google.com/sql/docs/postgres/db-versions',
    recommended_action: 'Ensure that all your PostgreSQL database instances are using the latest PostgreSQL database version.',
    apis: ['sql:list'],
    realtime_triggers:['cloudsql.instances.delete','cloudsql.instances.create'],

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

        const latestPostgreSQLVersion = 14;

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

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toUpperCase().startsWith('POSTGRES')) {
                    helpers.addResult(results, 0, 
                        'SQL instance database type is not of POSTGRES type', region, resource);
                    return;
                }

                if (sqlInstance.databaseVersion && parseInt(sqlInstance.databaseVersion.toUpperCase().split('POSTGRES_')[1]) >= latestPostgreSQLVersion) {
                    helpers.addResult(results, 0, 
                        `SQL instance is using Postgres major version ${sqlInstance.databaseVersion} which is the latest version`, region, resource);
                } else {
                    helpers.addResult(results, 2, 
                        `SQL instance is using Postgres major version ${sqlInstance.databaseVersion} which is not the latest version`, region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

