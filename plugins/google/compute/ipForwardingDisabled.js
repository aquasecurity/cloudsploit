var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'IP Forwarding Disabled',
    category: 'Compute',
    description: 'Ensures that IP forwarding is disabled on all instances',
    more_info: 'Disabling IP forwarding ensures that the instance only sends and receives packets with matching destination or source IPs.',
    link: 'https://cloud.google.com/vpc/docs/using-routes',
    recommended_action: 'IP forwarding settings can only be chosen when creating a new instance. Delete the affected instances and redeploy with IP forwarding disabled.',
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
                    if (instance.canIpForward) {
                        badInstances.push(instance.id)
                    }
                })
            });
            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query instances' , region);
            } else if (noInstances[region] &&
                zones[region] &&
                (noInstances[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 0, 'No instances found in the region' , region);
            } else if (badInstances.length) {
                var myInstanceStr = badInstances.join(", ");
                helpers.addResult(results, 2,
                    `Instance IP forwarding is enabled for the following instances: ${myInstanceStr}`, region);
            } else if (!badInstances.length) {
                helpers.addResult(results, 0,
                    'Instance IP forwarding is disabled for all instances in the region', region);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}