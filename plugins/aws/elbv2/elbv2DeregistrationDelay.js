var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ELBv2 Deregistration Delay',
    category: 'ELBv2',
    description: 'Ensures that AWS ELBv2 load balancers have deregistration delay configured.',
    more_info: 'AWS ELBv2 load balancers should have deregistration delay configured to avoid sending requests to targets that are deregistering.',
    link: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html#deregistration-delay',
    recommended_action: 'Update ELBv2 target group attributes and set the deregistration delay value',
    apis: ['ELBv2:describeLoadBalancers', 'ELBv2:describeTargetGroups', 'ELBv2:describeTargetGroupAttributes'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elbv2, function(region, rcb){
            var describeLoadBalancers = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!describeLoadBalancers) return rcb();

            if (describeLoadBalancers.err || !describeLoadBalancers.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Application/Network load balancers: ${helpers.addError(describeLoadBalancers)}`,
                    region);
                return rcb();
            }

            if (!describeLoadBalancers.data.length) {
                helpers.addResult(results, 0,
                    'No Application/Network load balancers found', region);
                return rcb();
            }

            async.each(describeLoadBalancers.data, function(elb, cb){
                var resource = elb.LoadBalancerArn;

                var describeTargetGroups = helpers.addSource(cache, source,
                    ['elbv2', 'describeTargetGroups', region, elb.DNSName]);

                if (!describeTargetGroups || describeTargetGroups.err || !describeTargetGroups.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for Application/Network load balancer target groups: ${helpers.addError(describeTargetGroups)}`,
                        region, resource);
                    return cb();
                }

                if(!describeTargetGroups.data.TargetGroups || !describeTargetGroups.data.TargetGroups.length){
                    helpers.addResult(results, 2,
                        'No Application/Network load balancer target groups found',
                        region, resource);
                    return cb();
                }

                async.each(describeTargetGroups.data.TargetGroups, function(targetGroup, tcb){
                    var describeTargetGroupAttributes = helpers.addSource(cache, source,
                        ['elbv2', 'describeTargetGroupAttributes', region, targetGroup.TargetGroupArn]);

                    if (!describeTargetGroupAttributes || describeTargetGroupAttributes.err || !describeTargetGroupAttributes.data
                            || !describeTargetGroupAttributes.data.Attributes || !describeTargetGroupAttributes.data.Attributes.length) {
                        helpers.addResult(results, 3,
                            `Unable to query for Application/Network load balancer target group attributes: ${helpers.addError(describeTargetGroupAttributes)}`,
                            region, resource);
                        return tcb();
                    }

                    var deregistationDelayConfigured = false;
                    for (var attribute of describeTargetGroupAttributes.data.Attributes) {
                        if (attribute.Key && attribute.Key === 'deregistration_delay.timeout_seconds' &&
                            attribute.Value && parseInt(attribute.Value) > 0) {
                            deregistationDelayConfigured = true;
                            break;
                        }
                    }

                    if (deregistationDelayConfigured) {
                        helpers.addResult(results, 0,
                            `Application/Network load balancer "${elb.LoadBalancerName}" has deregistration delay configured`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Application/Network load balancer "${elb.LoadBalancerName}" does not have deregistration delay configured`,
                            region, resource);
                    }

                    tcb();
                }, function(){
                    cb();
                });
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
