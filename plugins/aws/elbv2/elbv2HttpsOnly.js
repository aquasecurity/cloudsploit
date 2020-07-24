var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 HTTPS Only',
    category: 'ELBv2',
    description: 'Ensures ELBs are configured to only accept' +
        ' connections on HTTPS ports.',
    more_info: 'For maximum security, ELBs can be configured to only'+
        ' accept HTTPS connections. Standard HTTP connections '+
        ' will be blocked. This should only be done if the '+
        ' client application is configured to query HTTPS '+
        ' directly and not rely on a redirect from HTTP.',
    link: 'http://docs.aws.amazon.com/ElasticLoadBalancing/latest/DeveloperGuide/elb-security-policy-options.html',
    recommended_action: 'Remove non-HTTPS listeners from load balancer.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeListeners'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

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
                var describeListeners = helpers.addSource(cache, source,
                    ['elbv2', 'describeListeners', region, lb.DNSName]);

                // loop through listeners
                var non_https_listener = [];
                var noListeners = true;
                var elbArn = lb.LoadBalancerArn;
                if (describeListeners.data && describeListeners.data.Listeners && describeListeners.data.Listeners.length) {
                    noListeners = false;
                    describeListeners.data.Listeners.forEach(function(listener){
                        // if it is not https add errors to results
                        if (listener.Protocol != 'HTTPS'){
                            non_https_listener.push(
                                listener.Protocol + ' / ' +
                                listener.Port
                            );
                        }

                    });
                }
                if (non_https_listener && non_https_listener.length){
                    var msg = 'The following listeners are not using HTTPS-only: ';
                    helpers.addResult(results, 2,
                        msg + non_https_listener.join(', '), region, elbArn);
                }else if (non_https_listener && !non_https_listener.length) {
                    helpers.addResult(results, 0, 'All listeners are HTTPS-only', region, elbArn);
                } else if (noListeners) {
                    helpers.addResult(results, 0, 'No listeners found', region, elbArn);
                }
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
