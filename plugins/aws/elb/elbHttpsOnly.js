var async = require('async');
var helpers = require('../../../helpers/aws');

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
    apis: ['ELB:describeLoadBalancers', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
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
                // arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name
                var elbArn = 'arn:aws:elasticloadbalancing:' +
                              region + ':' + accountId + ':' +
                              'loadbalancer/' + lb.LoadBalancerName;

                // loop through listeners
                var non_https_listner = [];
                lb.ListenerDescriptions.forEach(function(listener){
                    // if it is not https add errors to results
                    if (listener.Listener.Protocol != 'HTTPS'){
                        non_https_listner.push(
                            listener.Listener.Protocol + ' / ' +  
                            listener.Listener.LoadBalancerPort
                        );
                    }

                });
                if (non_https_listner){
                    //helpers.addResult(results, 2, non_https_listner.join(', '), region);
                    var msg = 'The following listeners are not using HTTPS-only: ';
                    helpers.addResult(
                        results, 2, msg + non_https_listner.join(', '), region, elbArn
                    );
                }else{
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
