var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Connect Serial Ports Disabled',
    category: 'Compute',
    description: 'Ensure Enable Connecting to Serial Ports is not enabled for VM Instance',
    more_info: 'The Serial Console does not allow restricting IP Addresses, which allows any IP address to connect to instance.',
    link: 'https://cloud.google.com/compute/docs/instances/interacting-with-serial-console',
    recommended_action: '1.Enter the Compute Service. 2. Select the Instance. 3. Select Edit then deselect Enable Connecting to Serial Ports.',
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
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {

                        instance.metadata.items.forEach(item => {
                            if (item &&
                                item.key === 'serial-port-enable' &&
                                item.value === 'true') {
                                badInstances.push(instance.id)
                            }
                        })

                    }
                });

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
                    `Connecting to Serial Ports is Enabled for the following instances: ${myInstanceStr}`, region);
            } else if (!badInstances.length) {
                helpers.addResult(results, 0,
                    'Connecting to Serial Ports is disabled for all instances in the region', region);
            }
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};