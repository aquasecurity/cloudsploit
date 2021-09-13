var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Preemptibility Disabled',
    category: 'Compute',
    description: 'Ensure that preemptible Virtual Machine instances do not exist.',
    more_info: 'Preemptible instances are excess Compute Engine capacity, so their availability varies with usage. Compute Engine can terminate preemptible instances if it requires access to these resources for other tasks.',
    link: 'https://cloud.google.com/compute/docs/instances/preemptible',
    recommended_action: 'Ensure that your Google Compute Engine VM instances are not preemptible.',
    apis: ['instances:compute:list', 'projects:get'],

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
        async.each(regions.instances.compute, (region, rcb) => {
            var noInstances = [];
            var zones = regions.zones;
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone ]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3, 'Unable to query compute instances', region, null, null, instances.err);
                    return zcb();
                }

                if (!instances.data.length) {
                    noInstances.push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    let resource = helpers.createResourceName('instances', instance.name, project, 'zone', zone);
                    if (instance.scheduling && instance.scheduling.preemptible) {
                        helpers.addResult(results, 2,
                            'VM Instance is preemptible', region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'VM Instance is not preemptible', region, resource);
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