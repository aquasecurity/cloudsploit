var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Classic Load Balancers In Use',
    category: 'ELB',
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

            var classicLBFound = false;
            async.each(describeLoadBalancers.data, function(lb, cb){
                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                if (!lb.ListenerDescriptions.length) {
                    helpers.addResult(results, 0,
                        `ELB "${lb.LoadBalancerName}" is not using any listeners`,
                        region, elbArn);
                    return cb();
                }

                for (var listener of lb.ListenerDescriptions){
                    if (lb.Instances && lb.Instances.length && listener.Listener && ( listener.Listener.Protocol === 'HTTP' || listener.Listener.Protocol === 'HTTPS')) {
                        classicLBFound = true;
                        helpers.addResult(results, 2,
                            `HTTP/HTTPS application is using "${lb.LoadBalancerName}" Classic load balancer`,
                            region, elbArn);
                    }
                }

                cb();
            }, function(){
                if (!classicLBFound) {
                    helpers.addResult(results, 0,
                        'No HTTP/HTTPS application using Classic load balancer found',
                        region);
                }

                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};