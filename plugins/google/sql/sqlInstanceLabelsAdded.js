var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Instance Labels Added',
    category: 'SQL',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures SQL database instances have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/sql/docs/mysql/label-instance',
    recommended_action: 'Ensure labels are added for all SQL databases.',
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

                if (sqlInstance.settings && sqlInstance.settings.userLabels &&
                    Object.keys(sqlInstance.settings.userLabels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(sqlInstance.settings.userLabels).length} labels found for the SQL database`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'SQL database does not have any labels', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
