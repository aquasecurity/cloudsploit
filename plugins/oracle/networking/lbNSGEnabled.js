var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'LB Network Security Groups Enabled',
    category: 'Networking',
    description: 'Ensures Load Balancers are using network security groups to restrict network access.',
    more_info: 'Network security groups gives fine grained control of resources. Security rules associated with network security groups can be associated with specific resources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/networking_security.htm',
    recommended_action: 'Ensure Load Balancers are using network security groups to restrict network access.',
    apis: ['loadBalancer:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.loadBalancer, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var loadBalancers = helpers.addSource(cache, source,
                    ['loadBalancer', 'list', region]);

                if (!loadBalancers) return rcb();

                if (loadBalancers.err || !loadBalancers.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for load balancers: ' + helpers.addError(loadBalancers), region);
                    return rcb();
                }

                if (!loadBalancers.data.length) {
                    helpers.addResult(results, 0, 'No load balancers found', region);
                    return rcb();
                }

                var allLbs = true;
                loadBalancers.data.forEach(loadBalancer => {
                    if (loadBalancer.networkSecurityGroupIds &&
                        loadBalancer.networkSecurityGroupIds.length < 1) {
                        helpers.addResult(results, 2,
                            'Load Balancer has no network security groups connected', region, loadBalancer.id);
                        allLbs = false;
                    } else {

                    }
                });
                if (allLbs) {
                    helpers.addResult(results, 0,
                        `All Load balancers have network security groups Connected`, region);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};