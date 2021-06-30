var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Instance Level SSH Only',
    category: 'Compute',
    description: 'Ensures that instances are not configured to allow project-wide SSH keys',
    more_info: 'To support the principle of least privilege and prevent potential privilege escalation it is recommended that instances are not give access to project-wide SSH keys through instance metadata.',
    link: 'https://cloud.google.com/compute/docs/instances/adding-removing-ssh-keys',
    recommended_action: 'Ensure project-wide SSH keys are blocked for all instances.',
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
                    var found;
                    if (instance.metadata &&
                        instance.metadata.items &&
                        instance.metadata.items.length) {

                        found = instance.metadata.items.find(metaItem => metaItem.key === 'block-project-ssh-keys' &&
                            metaItem.value && metaItem.value.toUpperCase() === 'TRUE');
                    }

                    if (!found) notBlockedProjectSSHKey.push(instance.id);
                });
            });

            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query instances', region, null, null, myError);
            } else if (noInstances[region] &&
                zones[region] &&
                (noInstances[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 0, 'No instances found in the region' , region);
            } else if (notBlockedProjectSSHKey.length) {
                var myInstanceStr = notBlockedProjectSSHKey.join(", ");
                helpers.addResult(results, 2,
                    `Block project-wide SSH keys is disabled for the following instances: ${myInstanceStr}`, region);
            } else if (!notBlockedProjectSSHKey.length) {
                helpers.addResult(results, 0,
                    'Block project-wide SSH keys is enabled for all instances in the region', region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
