var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Shielded VM Enabled',
    category: 'Compute',
    description: 'Ensures that instances are configured with the shielded VM enabled',
    more_info: 'Shielded VM option should be configured to defend against the security attacks on the instances.',
    link: 'https://cloud.google.com/security/shielded-cloud/shielded-vm',
    recommended_action: 'Enable the shielded VM for all the instances for security reasons.',
    apis: ['instances:compute:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noInstances = {};
            var shieldedVmInstances = [];
            var nonShieldedVmInstances = [];
            async.each(zones[region], function(zone, zcb) {
                var instances = helpers.addSource(cache, source,
                    ['instances', 'compute','list', zone]);

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
                    if (instance.shieldedInstanceConfig &&
                        instance.shieldedInstanceConfig.enableVtpm &&
                        instance.shieldedInstanceConfig.enableIntegrityMonitoring) shieldedVmInstances.push(instance.id);
                    else nonShieldedVmInstances.push(instance.id);
                });
            });

            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query instances', region, null, null, myError);
            } 
            if (noInstances[region] &&
                zones[region] &&
                (noInstances[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 0, 'No instances found in the region' , region);
            } 
            if (shieldedVmInstances.length) {
                helpers.addResult(results, 0,
                    `Shielded VM security is enabled for the following instances: ${shieldedVmInstances.join(', ')}`, region);
            } 
            if (nonShieldedVmInstances.length) {
                var myInstanceStr = nonShieldedVmInstances.join(", ");
                helpers.addResult(results, 2,
                    `Shielded VM security is not enabled for the following instances: ${myInstanceStr}`, region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
