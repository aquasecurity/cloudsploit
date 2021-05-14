var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Default Service Account',
    category: 'Compute',
    description: 'Ensures that instances are not configured to use the default service account',
    more_info: 'Default service account has the editor role permissions. Due to security reasons it should not be used in any instance.',
    link: 'https://code.kiwi.com/towards-secure-by-default-google-cloud-platform-service-accounts-244ad9fc772',
    recommended_action: 'Ensure that default service account is not used for all the instances.',
    apis: ['instances:compute:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        var project = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);
        var defaultServiceAccount = project.data[0].defaultServiceAccount;

        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            var myError = {};
            var noInstances = {};
            var defaultServiceAccountInstances = [];
            var validServiceAccountInstances = [];
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
                    if (instance.serviceAccounts &&
                        instance.serviceAccounts.length) {
                        var found = instance.serviceAccounts.find(account => account.email == defaultServiceAccount);
                        if (found) {
                            defaultServiceAccountInstances.push(instance.id)
                        }
                        else {
                            validServiceAccountInstances.push(instance.id)
                        }
                    } else {
                        validServiceAccountInstances.push(instance.id)
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
            } if (defaultServiceAccountInstances.length) {
                var myInstanceStr = defaultServiceAccountInstances.join(", ");
                helpers.addResult(results, 2,
                    `Default service account is used for following instances: ${myInstanceStr}`, region);
            } if (validServiceAccountInstances.length) {
                var myInstanceStr = validServiceAccountInstances.join(", ");
                helpers.addResult(results, 0,
                    `Default service account is not used for following instances: ${myInstanceStr}`, region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
