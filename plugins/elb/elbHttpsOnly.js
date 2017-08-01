var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'ELB HTTPS Only',
    category: 'ELB',
    description: 'Ensures ELBs are configured to only accept' + 
                 ' connections on HTTPS ports.',
    more_info: 'For maximum security, ELBs can be configured to only'+
                ' accept HTTPS connections. Standard HTTP connections '+
                ' will be blocked. This should only be done if the '+
                ' client application is configured to query HTTPS '+
                ' directly and not rely on a redirect from HTTP.',
    link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
    apis: ['ELB:describeLoadBalancers'],

    run: function(cache, callback) {
        var results = [];
        var source = {};
        async.each(helpers.regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                // loop through listeners
                lb.ListenerDescriptions.forEach(function(listener){
                    // if it is not https add errors to results
                    if (listener.Listener.Protocol != 'HTTPS'){
                        helpers.addResult(
                            results, 2, 
                            'Remove Listener ' + 
                            listener.Listener.Protocol + '-' + 
                            listener.Listener.LoadBalancerPort + 
                            ' from ' + lb.LoadBalancerName,      
                            region
                        );
                    }

                });
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
