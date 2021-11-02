var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Connection Draining Enabled',
    category: 'ELB',
    domain: 'Content Delivery',
    description: 'Ensures that AWS ELBs have connection draining enabled.',
    more_info: 'Connection draining should be used to ensure that a Classic Load Balancer stops sending requests to instances that are de-registering or unhealthy, while keeping the existing connections open.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/config-conn-drain.html',
    recommended_action: 'Update ELBs to enable connection draining',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeLoadBalancerAttributes', 'STS:getCallerIdentity'],

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
                    `Unable to query for load balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(lb, cb){
                if (!lb.DNSName) return cb();

                var resource = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;

                var describeLoadBalancerAttributes = helpers.addSource(cache, source,
                    ['elb', 'describeLoadBalancerAttributes', region, lb.DNSName]);

                if (!describeLoadBalancerAttributes ||
                    describeLoadBalancerAttributes.err ||
                    !describeLoadBalancerAttributes.data ||
                    !describeLoadBalancerAttributes.data.LoadBalancerAttributes) {
                    helpers.addResult(results, 3,
                        `Unable to query load balancer attributes: ${helpers.addError(describeLoadBalancerAttributes)}`,
                        region, resource);
                    return cb();
                }

                if (describeLoadBalancerAttributes.data.LoadBalancerAttributes.ConnectionDraining &&
                    describeLoadBalancerAttributes.data.LoadBalancerAttributes.ConnectionDraining.Enabled) {
                    helpers.addResult(results, 0,
                        `ELB "${lb.LoadBalancerName}" has connection draining enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `ELB "${lb.LoadBalancerName}" does not have connection draining enabled`,
                        region, resource);
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