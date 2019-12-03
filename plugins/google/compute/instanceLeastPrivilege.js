var async   = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VM Instances with No Access',
    category: 'Compute',
    description: 'Ensure that instances are not configured to use the default service account with full access to all Cloud APIs.',
    more_info: 'To support principle of least privileges and prevent potential privilege escalation it is recommended that instances are not assigned to default service account Compute Engine default service account with Scope Allow full access to all Cloud APIs.',
    link: 'https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances',
    recommended_action: 'In Service Account Section, ensure Allow full access to all Cloud APIs is not selected if selecting the default service account.',
    apis: ['instances:compute:list'],

    run: function(cache, settings, callback) {

        var results = [];
        var source = {};
        var regions = helpers.regions();
        var myFullAccessScopes = {};
        async.each(regions.instances.compute, (region, rcb) => {
            var zones = regions.zones;
            myFullAccessScopes[region] = [];
            var myError = {};
            var noInstances = {};

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
                    if (instance.serviceAccounts && instance.serviceAccounts.length) {
                        instance.serviceAccounts.forEach(serviceAccount => {
                            if (serviceAccount.scopes &&
                                serviceAccount.scopes.indexOf('https://www.googleapis.com/auth/cloud-platform') > -1) {
                                myFullAccessScopes[region].push(serviceAccount.email)
                            }
                        });
                    }
                });
                return zcb();
            });

            if (myError[region] &&
                zones[region] &&
                (myError[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 3, 'Unable to query instances', region);

            } else if (noInstances[region] &&
                zones[region] &&
                (noInstances[region].join(',') === zones[region].join(','))) {
                helpers.addResult(results, 0, 'No instances found in the region' , region);

            } else if (myFullAccessScopes[region].length) {
                var myScopesStr = myFullAccessScopes[region].join(', ');
                helpers.addResult(results, 2,
                    `The following Service Accounts have full access: ${myScopesStr}` , region);

            } else if (!myFullAccessScopes[region].length){
                helpers.addResult(results, 0,
                    'All instance service accounts follow least privilege' , region);
            }

            rcb();
        }, function() {
            callback(null, results, source);
            // console.log("Results=", results);
        });
    }
};
