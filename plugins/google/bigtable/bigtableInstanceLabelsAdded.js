var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'BigTable Instance Labels Added',
    category: 'BigTable',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that all BigTable instances have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/bigtable/docs/creating-managing-labels',
    recommended_action: 'Ensure labels are added to all BigTable instances.',
    apis: ['bigtable:list'],
    realtime_triggers: ['bigtable.admin.BigtableInstanceAdmin.PartialUpdateInstance','bigtable.admin.BigtableInstanceAdmin.CreateInstance','bigtable.admin.BigtableInstanceAdmin.DeleteInstance'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        async.each(regions.bigtable, function(region, rcb){
            let instances =  helpers.addSource(
                cache, source, ['bigtable', 'list', region]);

            if (!instances) return rcb();

            if (instances.err || !instances.data) {
                helpers.addResult(results, 3, 'Unable to query BigTable instances', region, null, null, instances.err);
                return rcb();
            }

            if (!instances.data.length) {
                helpers.addResult(results, 0, 'No BigTable instances found', region);
                return rcb();
            }

            instances.data.forEach(instance => {

                if (instance.labels &&
                    Object.keys(instance.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(instance.labels).length} labels found for BigTable instance`, region, instance.name);
                } else {
                    helpers.addResult(results, 2,
                        'BigTable instance does not have any labels', region, instance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};