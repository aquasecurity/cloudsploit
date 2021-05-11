var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Public Access Disabled',
    category: 'Compute',
    description: 'Ensures that instances are not configured to allow public access',
    more_info: 'Public IP address can cause security issues. To avoid the public access external ips should not be enabled.',
    link: 'https://www.assured.se/2019/12/19/gcp-security/',
    recommended_action: 'Ensure external access is disabled for all the instances.',
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
                    if (instance.networkInterfaces &&
                        instance.networkInterfaces.length) {
                        var networkObject = instance.networkInterfaces.find(
                            networkObject => networkObject.accessConfigs && networkObject.accessConfigs);
                        if (networkObject) {
                            publicAccessInstances.push(instance.id)
                        }
                        else {
                            privateInstances.push(instance.id)
                        }
                    }
                });
            });

            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query instances' , region);
            } if (noInstances[region] &&
                zones[region] &&
                (noInstances[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 0, 'No instances found in the region' , region);
            } if (publicAccessInstances.length) {
                var myInstanceStr = publicAccessInstances.join(", ");
                helpers.addResult(results, 2,
                    `Public access is enabled for following instances: ${myInstanceStr}`, region);
            } if (privateInstances.length) {
                var myInstanceStr = privateInstances.join(", ");
                helpers.addResult(results, 0,
                    `Public access is disabled for following instances: ${myInstanceStr}`, region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
