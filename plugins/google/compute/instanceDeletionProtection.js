var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Instance Deletion Protection',
    category: 'Compute',
    description: 'Ensure that Virtual Machine instances have deletion protection enabled.',
    more_info: 'VM instances should have deletion protection enabled in order to prevent them for being accidentally deleted.',
    link: 'https://cloud.google.com/compute/docs/instances/preventing-accidental-vm-deletion',
    recommended_action: 'Modify VM instances to enable deletion protection',
    apis: ['instances:compute:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noInstances = {};
            var badInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone ]);

                if (!instances) return zcb();

                if (instances.err || !instances.data) {
                    if (!myError[region]) {
                        myError[region] = [];
                    }
                    myError[region].push(zone);
                    myError[region][zone] = instances.err;
                    return zcb();
                }

                if (!instances.data.length) {
                    if (!noInstances[region]) {
                        noInstances[region] = [];
                    }
                    noInstances[region].push(zone);
                    return zcb();
                }

                instances.data.forEach(instance => {
                    if (!instance.deletionProtection) {
                        badInstances.push(instance.id)
                    }
                });
                zcb();
            }, function() {
                if (myError[region] &&
                    zones[region] &&
                    (myError[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 3, 'Unable to query instances', region, null, null, myError);
                } else if (noInstances[region] &&
                    zones[region] &&
                    (noInstances[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 0, 'No instances found in the region' , region);
                } else if (badInstances.length) {
                    var myInstanceStr = badInstances.join(", ");
                    helpers.addResult(results, 2,
                        `Instance deletion protection is disabled for the following instances: ${myInstanceStr}`, region);
                } else if (!badInstances.length) {
                    helpers.addResult(results, 0,
                        'Instance deletion protection is enabled for all instances in the region', region);
                }
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};