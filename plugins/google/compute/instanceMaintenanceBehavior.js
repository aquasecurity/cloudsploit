var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Maintenance Behavior',
    category: 'Compute',
    description: 'Ensure that "On Host Maintenance" configuration is set to Migrate for VM instances.',
    more_info: 'When Google Compute Engine performs regular maintenance of its infrastructure, it migrates your VM instances to other hardware if you have configured the availability policy for the instance to use live migration. This prevents your applications from experiencing disruptions during these events.',
    link: 'https://cloud.google.com/compute/docs/instances/setting-instance-scheduling-options',
    recommended_action: 'Ensure that your Google Compute Engine VM instances are configured to use live migration.',
    apis: ['instances:compute:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var noInstances = [];
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
                   
                    if (instance.scheduling && instance.scheduling.onHostMaintenance && instance.scheduling.onHostMaintenance.toUpperCase() == 'MIGRATE') {
                        helpers.addResult(results, 0,
                            'Instance Maintenance Behavior is set to MIGRATE', region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            'Instance Maintenance Behavior is not set to MIGRATE', region, resource);
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
