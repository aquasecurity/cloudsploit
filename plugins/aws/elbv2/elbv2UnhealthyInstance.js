var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Unhealthy Instances',
    category: 'ELBv2',
    domain: 'Content Delivery',
    severity: 'High',
    description: 'Ensures that ELBv2 have healthy instances attached',
    more_info: 'ELBs should have healthy instances to ensure proper load balancing and availability. ' +
        'Unhealthy instances can result in degraded performance or service disruptions.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/target-group-health-checks.html',
    recommended_action: 'Investigate and resolve the health issues with the instances attached to the ELB.',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups', 'ELBv2:describeTargetHealth'],
    realtime_triggers: ['elasticloadbalancing:CreateLoadBalancer', 'elasticloadbalancing:ModifyTargetGroups', 'elasticloadbalancing:RegisterTarget', 'elasticloadbalancing:DeregisterTargets', 'elasticloadbalancing:DeleteLoadBalancer', 'elasticloadbalancing:DeleteTargetGroup'],

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
                    'Unable to query for Application/Network load balancers: ' + helpers.addError(describeLoadBalancers), region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0, 'No Application/Network load balancers present', region);
                return rcb();
            }

            describeLoadBalancers.data.forEach(function(lb) {
                var resource = lb.LoadBalancerArn;
                var unhealthyInstances = 0;
                var describeTargetGroups = helpers.addSource(cache, source,
                    ['elbv2', 'describeTargetGroups', region, lb.DNSName]);

                if (!describeTargetGroups || describeTargetGroups.err || !describeTargetGroups.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for Application/Network load balancer target groups: ${helpers.addError(describeTargetGroups)}`,
                        region, resource);
                    return;
                }

                if (!describeTargetGroups.data.TargetGroups || !describeTargetGroups.data.TargetGroups.length) {
                    helpers.addResult(results, 2, 'No Application/Network load balancer target groups found', region, resource);
                    return;
                }

                describeTargetGroups.data.TargetGroups.forEach(function(tg) {
                    var describeTargetHealth = helpers.addSource(cache, source,
                        ['elbv2', 'describeTargetHealth', region, tg.TargetGroupArn]);

                    if (!describeTargetHealth || describeTargetHealth.err || !describeTargetHealth.data
                            || !describeTargetHealth.data.TargetHealthDescriptions || !describeTargetHealth.data.TargetHealthDescriptions.length) {
                        return;
                    }

                    describeTargetHealth.data.TargetHealthDescriptions.forEach(healthDescription => {
                        if (healthDescription.Target && healthDescription.Target.Id &&
                            healthDescription.TargetHealth && healthDescription.TargetHealth.State === 'unhealthy') {
                            unhealthyInstances = unhealthyInstances + 1;
                        }
                    });
                });

                if (unhealthyInstances > 0) {
                    helpers.addResult(results, 2,
                        `Application/Network load balancer has ${unhealthyInstances} unhealthy instance(s) associated`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'Application/Network load balancer does not have any unhealthy instance associated',
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
