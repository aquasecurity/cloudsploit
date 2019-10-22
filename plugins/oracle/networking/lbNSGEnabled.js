var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'LB Network Security Groups Enabled',
    category: 'Networking',
    description: 'Ensure Load Balancers are using Network Security Groups to restrict network access.',
    more_info: 'Network Security Groups gives fine grained control of resources. Security rules associated with Network Security Groups can be associated with specific resources.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Security/Reference/networking_security.htm',
    recommended_action: '1. Enter the Load Balancer Service. 2. Select the Load Balancer. 3. In the load Balancer Information, Edit Network Security Groups. 4. Select the best Network Security Group for the load balancer.',
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
                };

                if (!loadBalancers.data.length) {
                    helpers.addResult(results, 0, 'No load balancers present', region);
                    return rcb();
                };

                var allLbs = true;
                loadBalancers.data.forEach(loadBalancer => {
                    if (loadBalancer.networkSecurityGroupIds &&
                        loadBalancer.networkSecurityGroupIds.length < 1) {
                        helpers.addResult(results, 2,
                            'Load Balancer has no Network Security Groups connected', region, loadBalancer.id);
                        allLbs = false;
                    } else {

                    };
                });
                if (allLbs) {
                    helpers.addResult(results, 0,
                        `All Load balancers have Network Security Groups Connected`, region);
                };
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};