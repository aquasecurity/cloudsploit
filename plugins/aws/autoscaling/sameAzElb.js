var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling Group Missing ELB',
    category: 'AutoScaling',
    description: 'Ensures all autoscaling groups are referencing active load balancers.',
    more_info: 'Each autoscaling group should with a load balancer configured should reference an active ELB.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Ensure that the autoscaling group load balancer has not been deleted. If so, remove it from the ASG.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancer'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var autoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!autoScalingGroups) return rcb();

            if (autoScalingGroups.err || !autoScalingGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for AutoScaling groups: ' + 
                    helpers.addError(autoScalingGroups), region);
                return rcb();
            }

            if (!autoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No AutoScaling groups found', region);
                return rcb();
            }

            autoScalingGroups.data.forEach(function(asg){
                asgAvailabilityZones = asg.AvailabilityZones;
                if(asg.HealthCheckType == "ELB") {
                    if (asg.LoadBalancerNames) {
                        // create ELBs and check
                        asg.LoadBalancerNames.forEach(function(elbName){
                            var elasticLoadBalancer = helpers.addSource(cache, source,
                                ['autoscaling', 'describeLoadBalancers', region, elbName]);

                            if(!elasticLoadBalancer || !elasticLoadBalancer.data || !elasticLoadBalancer.data.LoadBalancerDescriptions) {
                                console.log('Load balancer not found in AutoScaling group ' + elbName);
                                helpers.addResult(results, 2,
                                    'Load balancer not found in AutoScaling group',
                                    region, elbName);
                            } 
                            else {
                                var differentAzFound = false;
                                elbAvailabilityZones = elasticLoadBalancer.LoadBalancerDescriptions.AvailabilityZones;
                                elbAvailabilityZones.foreach(function(elbAz){
                                    if(!asgAvailabilityZones.includes(elbAz)) {
                                        differentAzFound = true;
                                    }
                                });
                                if(differentAzFound) {
                                    console.log('Load balancer ' + elbName + ' is not in the same AZ as of AutoScaling group');
                                    helpers.addResult(results, 2, 'Load balancer ' + elbName + ' is not in the same AZ as of AutoScaling group', region, asg.autoScalingGroupName);
                                }
                                else {
                                    console.log('Load balancer ' + elbName + ' is in the same AZ as of AutoScaling group');
                                    helpers.addResult(results, 0, 'Load balancer ' + elbName + ' is in the same AZ as of AutoScaling group', region, asg.autoScalingGroupName);
                                }
                            }
                        });
                    }
                    else {
                        console.log('Load balancer not found in AutoScaling group');
                        helpers.addResult(results, 2,
                            'Load balancer not found in AutoScaling group',
                            region, elbName);
                    }
                }
                else {
                    console.log('AutoScaling group does not utilize a load balancer');
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, elbName);
                }

            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
