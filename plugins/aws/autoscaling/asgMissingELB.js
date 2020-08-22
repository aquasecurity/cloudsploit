var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling Group Missing ELB',
    category: 'AutoScaling',
    description: 'Ensures all AutoScaling groups are referencing active load balancers.',
    more_info: 'Each AutoScaling group with a load balancer configured should reference an active ELB.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Ensure that the autoscaling group load balancer has not been deleted. If so, remove it from the ASG.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers'],

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

            if (!autoScalingGroups || !elasticLoadBalancers) return rcb();

            if (autoScalingGroups.err || !autoScalingGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for AutoScaling groups: ' +  helpers.addError(autoScalingGroups), region);
                return rcb();
            }

            if (elasticLoadBalancers.err || !elasticLoadBalancers.data) {
                helpers.addResult(results, 3, 'Unable to query for load balancers: ' +  helpers.addError(elasticLoadBalancers), region);
                return rcb();
            }

            if (elasticLoadBalancersV2.err || !elasticLoadBalancersV2.data) {
                helpers.addResult(results, 3, 'Unable to query for Application/Network load balancers: ' +  helpers.addError(elasticLoadBalancersV2), region);
                return rcb();
            }
            
            if (!autoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No AutoScaling group found', region);
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

            var elbFound = false;
            autoScalingGroups.data.forEach(function(asg){
                if(asg.HealthCheckType == 'ELB') {
                    if (asg.LoadBalancerNames && asg.LoadBalancerNames.length) {
                        if (!elasticLoadBalancers.data.length) {
                            helpers.addResult(results, 2, 'No load balancers found', region);
                            return rcb();
                        }
                        asg.LoadBalancerNames.forEach(function(elbName){
                            elbFound = false;
                            elasticLoadBalancers.data.forEach(function(elb) {
                                if(elbName == elb.LoadBalancerName) {
                                    elbFound = true;
                                    return;
                                }
                            });
                            if(!elbFound){
                                helpers.addResult(results, 2, 'AutoScaling group utilizes an inactive load balancer "'+ elbName + '"', region, elbName);
                            }
                            else {
                                helpers.addResult(results, 0, 'AutoScaling group utilizes active load balancer "'+ elbName + '"', region, elbName);
                            }
                        });
                    }
                    else {
                        helpers.addResult(results, 2, 'AutoScaling group does not have any Load Balancer associated', region, asg.AutoScalingGroupName);
                    }
                }
                else {
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, asg.AutoScalingGroupName);
                }

            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
