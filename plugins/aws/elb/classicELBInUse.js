var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Classic Load Balancers In Use',
    category: 'ELB',
    domain: 'Content Delivery',
    description: 'Ensures that HTTP/HTTPS applications are using Application Load Balancer instead of Classic Load Balancer.',
    more_info: 'HTTP/HTTPS applications should use Application Load Balancer instead of Classic Load Balancer for cost and web traffic distribution optimization.',
    link: 'https://aws.amazon.com/elasticloadbalancing/features/',
    recommended_action: 'Detach Classic Load balancer from HTTP/HTTPS applications and attach Application Load Balancer to those applications',
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
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`, region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                if (!lb.ListenerDescriptions.length) {
                    helpers.addResult(results, 0,
                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
                        region, elbArn);
                    return cb();
                }

                let found;

                if (lb.Instances && lb.Instances.length) {
                    found = lb.ListenerDescriptions.find(listener => listener.Listener && (listener.Listener.Protocol === 'HTTP' || listener.Listener.Protocol === 'HTTPS'));
                }

                if (!found) {
                    helpers.addResult(results, 0,
                        `Classic load balancer "${lb.LoadBalancerName}" is not in use`,
                        region, elbArn);
                } else {
                    helpers.addResult(results, 2,
                        `Classic load balancer "${lb.LoadBalancerName}" is in use`,
                        region, elbArn);
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