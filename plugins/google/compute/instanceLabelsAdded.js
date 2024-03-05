var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Labels Added',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that all Virtual Machine instances have labels added.',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/compute/docs/labeling-resources',
    recommended_action: 'Ensure labels are added to all VM instances.',
    apis: ['compute:list'],
    realtime_triggers: ['compute.instances.insert', 'compute.instances.delete', 'compute.instances.setLabels'],

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

        var project = projects.data[0].name;

        async.each(regions.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['compute','list', zone ]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);

                    if (instance.labels &&
                        Object.keys(instance.labels).length) {
                        helpers.addResult(results, 0,
                            `${Object.keys(instance.labels).length} labels found for VM instance.`, region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'VM instance does not have any labels', region, resource);
                    }
                });
                zcb();
            }, function() {
                if (noInstances.length) {
                    helpers.addResult(results, 0, `No instances found in following zones: ${noInstances.join(', ')}`, region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};