var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Listener Security',
    category: 'ELB',
    description: 'Ensures that AWS ELB listeners are using a secure protocol (HTTPS or SSL).',
    more_info: 'ELB listeners should use a secure protocol (HTTPS or SSL) to encrypt the communication between the client and load balancers.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html',
    recommended_action: 'Update ELB configurations to use listeners with HTTPS or SSL protocols (an X.509 SSL certificate is required)',
    apis: ['ELB:describeLoadBalancers', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.elb, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for load balancers: ' + ${helpers.addError(describeLoadBalancers)}`, region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            describeLoadBalancers.data.forEach(function(lb){
                if(!lb.LoadBalancerName) return;

                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
                if (!lb.ListenerDescriptions || !lb.ListenerDescriptions.length) {
                    helpers.addResult(results, 2,
                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
                        region, resource);
                    return;
                }

                var insecureListeners = [];
                lb.ListenerDescriptions.forEach(function(listener){
                    if (listener.Listener.Protocol !== 'HTTPS' && listener.Listener.Protocol !== 'SSL') {
                        insecureListeners.push(
                            `${listener.Listener.Protocol}/${listener.Listener.LoadBalancerPort}`
                        );
                    }
                });

                if (insecureListeners.length) {
                    helpers.addResult(results,2, 
                        `ELB listener "${lb.LoadBalancerName}" is using these insecure protocols: ${insecureListeners.join(', ')}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `ELB listener "${lb.LoadBalancerName}" is using secure protocols only`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
