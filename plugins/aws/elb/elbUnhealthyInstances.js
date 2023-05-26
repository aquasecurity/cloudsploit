var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELB Unhealthy Instances',
    category: 'ELB',
    domain: 'Content Delivery',
    description: 'Detects ELBs that have unhealthy instances attached',
    more_info: 'ELBs should have healthy instances attached to ensure proper load balancing and availability. Unhealthy instances can indicate issues with the backend server resources.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-healthchecks.html',
    recommended_action: 'Investigate and resolve the health issues of the instances attached to the ELB.',
    apis: ['ELB:describeLoadBalancers', 'ELB:describeInstanceHealth', 'STS:getCallerIdentity'],

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
                var elbArn = 'arn:aws:elasticloadbalancing:' +
                              region + ':' + accountId + ':' +
                              'loadbalancer/' + lb.LoadBalancerName;

                var describeInstanceHealth = helpers.addSource(cache, source,
                    ['elb', 'describeInstanceHealth', region, lb.DNSName]);

                if (!describeInstanceHealth) return cb();

                if (describeInstanceHealth.err || !describeInstanceHealth.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instance health: ' + helpers.addError(describeInstanceHealth), region, elbArn);
                    return cb();
                }
                var instanceStates = describeInstanceHealth.data.InstanceStates;
                if (!Array.isArray(instanceStates)) {
                    helpers.addResult(results, 3, 'Invalid instance states data for ELB: ' + lb.LoadBalancerName, region, elbArn);
                    return cb();
                }
                
                var unhealthyInstances = instanceStates.filter(function (instance) {
                    return instance.State === "OutOfService";
                });
                
                if (unhealthyInstances.length > 0) {
                    helpers.addResult(results, 2, `AWS ELB "${lb.LoadBalancerName}" has unhealthy instances`, region, elbArn);
                } else {
                    helpers.addResult(results, 0, `AWS ELB "${lb.LoadBalancerName}" does not have unhealthy instances`, region, elbArn);
                }
                
                cb();
            },function(){
              rcb();
         });
       }, function(){
           callback(null, results, source);
       });
   }
};
