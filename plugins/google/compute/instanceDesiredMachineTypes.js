var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Desired Machine Type',
    category: 'Compute',
    description: 'Ensures that Virtual Machine instances are of given types.',
    more_info: 'Virtual Machine instance should be of the given types to ensure the internal compliance and prevent unexpected billing charges.',
    link: 'https://cloud.google.com/compute/docs/machine-types',
    recommended_action: 'Stop the Virtual Machine instance, change the machine type to the desired type  and restart the instance.',
    apis: ['instances:compute:list', 'projects:get'],
    settings: {
        instance_desired_machine_types: {
            name: 'Instance Desired Machine Types',
            description: 'Desired Virtual Machine instance type',
            regex: '^.*$',
            default: ''
        },
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var instance_desired_machine_types = settings.instance_desired_machine_types || this.settings.instance_desired_machine_types.default;
        if (!instance_desired_machine_types.length) return callback(null, results, source);
        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);
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
                    ['instances', 'compute', 'list', zone]);

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
                    if (instance.machineType && instance_desired_machine_types.includes((instance.machineType.split('machineTypes/')[1]))) {
                        helpers.addResult(results, 0,
                            'Virtual Machine instance has desired machine type', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Virtual Machine instance does not have desired machine type', region, resource);
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
