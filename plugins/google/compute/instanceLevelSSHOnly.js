var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Level SSH Only',
    category: 'Compute',
    description: 'Ensure that instances are not configured to allow Project Wide SSH keys.',
    more_info: 'To support principle of least privileges and prevent potential privilege escalation it is recommended that instances are not accessible from project wide SSH keys. These keys are accessible through metadata and can become comprimised.',
    link: 'https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys',
    recommended_action: '1. Enter the Compute Service. 2. Select the Instance in question. 3. Select Edit at the top of the page. 4. Under SSH Keys ensure that Block Project-Wide SSH Keys is enabled.',
    apis: ['instances:compute:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noInstances = {};
            var notBlockedProjectSSHKey = [];
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
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {

                        instance.metadata.items.forEach(metaItem => {
                            if (metaItem.key === 'block-project-ssh-keys' && metaItem.value === 'FALSE') {
                                notBlockedProjectSSHKey.push(instance.id)
                            }
                        });
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
            } else if (notBlockedProjectSSHKey.length) {
                var myInstanceStr = notBlockedProjectSSHKey.join(", ");
                helpers.addResult(results, 2,
                    `Block Project-wide SSH Keys is Disabled for the following instances: ${myInstanceStr}`, region);
            } else if (!notBlockedProjectSSHKey.length) {
                helpers.addResult(results, 0,
                    'Block Project-wide SSH Keys is enabled for all instances in the region', region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
