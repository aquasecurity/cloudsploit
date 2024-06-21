var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Unhealthy Instances',
    category: 'ELB',
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensures that AWS ELBs have healthy instances attached',
    more_info: 'ELBs should have healthy instances attached to ensure proper load balancing and availability. The status of the instances that are healthy should be InService.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-healthchecks.html#check-instance-health',
    recommended_action: 'Investigate and resolve the health issues of the instances attached to the ELB.',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeInstanceHealth', 'STS:getCallerIdentity'],
    realtime_triggers: ['elasticloadbalancing:CreateLoadBalancer', 'elasticloadbalancing:RegisterInstancesWithLoadBalancer', 'elasticloadbalancing:DeregisterInstancesWithLoadBalancer',  'elasticloadbalancing:DeleteLoadBalancer'],

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
                    'Unable to query for load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No load balancers present', region);
                return rcb();
            }

            describeLoadBalancers.data.forEach(function(lb) {
                
                if (!lb.LoadBalancerName) return;

                var elbArn = `arn:${awsOrGov}:elasticloadbalancing:${region}:${accountId}:loadbalancer/${lb.LoadBalancerName}`;
            
                var describeInstanceHealth = helpers.addSource(cache, source,
                    ['elb', 'describeInstanceHealth', region, lb.DNSName]);
            
                if (!describeInstanceHealth) return;
            
                if (describeInstanceHealth.err || !describeInstanceHealth.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for instance health: ${helpers.addError(describeInstanceHealth)}`, region, elbArn);
                    return;
                }
            
                var instanceStates = describeInstanceHealth.data.InstanceStates;
            
                var unhealthyInstances = instanceStates.filter(function(instance) {
                    return instance.State === 'OutOfService';
                });

                if (unhealthyInstances.length > 0) {
                    var length = unhealthyInstances.length;
                    helpers.addResult(results, 2, `ELB has ${length} unhealthy instance(s)`, region, elbArn);
                } else {
                    helpers.addResult(results, 0, 'ELB does not have unhealthy instance', region, elbArn);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    },
};
