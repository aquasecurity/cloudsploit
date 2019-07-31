var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Load Balancer HTTPS Only',
    category: 'Networking',
    description: 'Ensures LBs are configured to only accept' + 
                 ' connections on HTTPS ports.',
    more_info: 'For maximum security, LBs can be configured to only'+
                ' accept HTTPS connections. Standard HTTP connections '+
                ' will be blocked. This should only be done if the '+
                ' client application is configured to query HTTPS '+
                ' directly and not rely on a redirect from HTTP.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managinglisteners.htm',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
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

                async.each(loadBalancers.data, function(lb, cb) {
                    // loop through listeners
                    var non_https_listner = [];

                    Object.keys(lb.listeners).forEach(function(listener_name){
                        var listener = lb.listeners[listener_name];
                        // if it is not https add errors to results
                        if (listener.protocol != 'HTTPS'){
                            non_https_listner.push(
                                listener.protocol + ' / ' +
                                listener.port
                            );
                        }

                    });

                    if (non_https_listner){
                        //helpers.addResult(results, 2, non_https_listner.join(', '), region);
                        msg = "The following listeners are not HTTPS-only: ";
                        helpers.addResult(
                            results, 2, msg + non_https_listner.join(', '), region, lb.id
                        );
                    }else{
                        helpers.addResult(results, 0, 'No listeners found', region, lb.id);
                    }

                    cb();
                });
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};