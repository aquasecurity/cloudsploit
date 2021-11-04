var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Automatic Restart Enabled',
    category: 'Compute',
    domain: 'Compute',
    description: 'Ensure that Virtual Machine instances have automatic restart feature enabled.',
    more_info: 'Automatic Restart sets the virtual machine restart behavior when an instance is crashed or stopped by the system. If it is enabled, Google Cloud Compute Engine restarts the instance if it crashes or is stopped.',
    link: 'https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options#autorestart',
    recommended_action: 'Ensure automatic restart is enabled for all virtual machine instances.',
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
                    if (instance.scheduling && instance.scheduling.automaticRestart) {
                        helpers.addResult(results, 0,
                            'Automatic Restart is enabled for the instance', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Automatic Restart is disabled for the instance', region, resource);
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