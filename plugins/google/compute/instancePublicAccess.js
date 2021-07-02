var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Public Access Disabled',
    category: 'Compute',
    description: 'Ensures that compute instances are not configured to allow public access.',
    more_info: 'Compute Instances should always be configured behind load balancers instead of having public IP addresses ' +
        'in order to minimize the instance\'s exposure to the internet.',
    link: 'https://cloud.google.com/compute/docs/ip-addresses/reserve-static-external-ip-address',
    recommended_action: 'Modify compute instances and set External IP to None for network interface',
    apis: ['instances:compute:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noInstances = {};
            var publicAccessInstances = [];
            var privateInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone]);

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
                    if (instance.name && instance.name.startsWith('gke-')) return;

                    if (instance.networkInterfaces &&
                        instance.networkInterfaces.length) {
                        var networkObject = instance.networkInterfaces.find(networkObject => networkObject.accessConfigs);
                        if (networkObject) {
                            publicAccessInstances.push(instance.id)
                        }
                        else {
                            privateInstances.push(instance.id)
                        }
                    }
                });
                zcb();
            }, function() {
                if (myError[region] &&
                    zones[region] &&
                    (myError[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 3, 'Unable to query instances' , region);
                }
                if (noInstances[region] &&
                    zones[region] &&
                    (noInstances[region].join(',') === zones[region].join(','))) {
                    helpers.addResult(results, 0, 'No instances found in the region' , region);
                }
                if (publicAccessInstances.length) {
                    helpers.addResult(results, 2,
                        `Public access is enabled for these instances: ${publicAccessInstances.join(', ')}`, region);
                }
                if (privateInstances.length) {
                    helpers.addResult(results, 0,
                        `Public access is disabled for these instances: ${privateInstances.join(', ')}`, region);
                }
    
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
