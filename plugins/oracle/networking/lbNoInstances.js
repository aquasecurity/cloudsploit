var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Load Balancer No Instances',
    category: 'Networking',
    description: 'Detects LBs that have no backend instances attached',
    more_info: 'All LBs should have backend server resources. ' +
               'Those without any are consuming costs without providing ' +
               'any functionality. Additionally, old ELBs with no instances ' +
               'present a security concern if new instances are accidentally attached.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/GSG/Tasks/loadbalancing.htm',
    recommended_action: 'Delete old LBs that no longer have backend resources.',
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
                    helpers.addResult(results, 0, 'No load balancers present', region);
                    return rcb();
                }

                async.each(loadBalancers.data, function (lb, cb) {
                    lbBackend = lb.backendSets['bs_' + lb.displayName];
                    if (lbBackend &&
                        lbBackend.backends &&
                        lbBackend.backends.length) {
                        helpers.addResult(results, 0, 'ELB has ' + lb[lb.displayName].backends.length + ' backend instances', region, lb.id);
                    } else {
                        helpers.addResult(results, 1, 'ELB does not have backend instances', region, lb.id);
                    }
                    cb();
                })
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};