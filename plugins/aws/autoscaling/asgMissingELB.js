var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Group Missing ELB',
    category: 'AutoScaling',
    description: 'Ensures all Auto Scaling groups are referencing active load balancers.',
    more_info: 'Each Auto Scaling group with a load balancer configured should reference an active ELB.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Ensure that the Auto Scaling group load balancer has not been deleted. If so, remove it from the ASG.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers', 'ELBv2:describeLoadBalancers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var elbNames = [];

        async.each(regions.autoscaling, function(region, rcb){
            var autoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            var elasticLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            var elasticLoadBalancersV2 = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!autoScalingGroups || !elasticLoadBalancers || !elasticLoadBalancersV2) return rcb();

            if (autoScalingGroups.err || !autoScalingGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for Auto Scaling groups: ' +  helpers.addError(autoScalingGroups), region);
                return rcb();
            }

            if (elasticLoadBalancers.err || !elasticLoadBalancers.data) {
                helpers.addResult(results, 3, 'Unable to query for Classic load balancers: ' +  helpers.addError(elasticLoadBalancers), region);
                return rcb();
            }

            if (elasticLoadBalancersV2.err || !elasticLoadBalancersV2.data) {
                helpers.addResult(results, 3, 'Unable to query for Application/Network load balancers: ' +  helpers.addError(elasticLoadBalancersV2), region);
                return rcb();
            }
            
            if (!autoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling group found', region);
                return rcb();
            }
            
            if (elasticLoadBalancers.data.length) {
                elasticLoadBalancers.data.forEach(function(elb) {
                    if(elb.LoadBalancerName) {
                        elbNames.push(elb.LoadBalancerName);
                    }
                });
            }

            if (elasticLoadBalancersV2.data.length) {
                elasticLoadBalancersV2.data.forEach(function(elbv2) {
                    if(elbv2.LoadBalancerName) {
                        elbNames.push(elbv2.LoadBalancerName);
                    }
                });
            }

            autoScalingGroups.data.forEach(function(asg){
                var resource = asg.AutoScalingGroupARN;
                var inactiveElbs = [];
                if(asg.HealthCheckType && asg.HealthCheckType === 'ELB') {
                    if (asg.LoadBalancerNames && asg.LoadBalancerNames.length) {
                        asg.LoadBalancerNames.forEach(function(elbName){
                            if(!elbNames.length || !elbNames.includes(elbName)) {
                                inactiveElbs.push(elbName);
                            }
                        });

                        if (inactiveElbs.length){
                            helpers.addResult(results, 2,
                                'Auto Scaling group utilizes these inactive load balancers: '+ inactiveElbs.join(', '),
                                region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                'Auto Scaling group: ' + asg.AutoScalingGroupName + ' utilizes active load balancers',
                                region, resource);
                        }
                    }
                    else {
                        helpers.addResult(results, 2,
                            'Auto Scaling group does not have any Load Balancer associated', region, resource);
                    }
                }
                else {
                    helpers.addResult(results, 0,
                        'Auto Scaling group does not utilize a load balancer', region, resource);
                }

            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
