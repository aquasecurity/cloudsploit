var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling ELB Same Availability Zone',
    category: 'AutoScaling',
    description: 'Ensures all autoscaling groups with attached ELBs are operating in the same availability zone.',
    more_info: 'To work properly and prevent orphaned instances, ELBs must be created in the same availability zones as the backend instances in the autoscaling group.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html',
    recommended_action: 'Update the ELB to use the same availability zones as the autoscaling group.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers', 'ELBv2:describeLoadBalancers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var loadBalancers = {};

        async.each(regions.autoscaling, function(region, rcb){
            var autoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);
                
            var elasticLoadBalancers = helpers.addSource(cache, source,
                ['elb', 'describeLoadBalancers', region]);

            var elasticLoadBalancersV2 = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!autoScalingGroups || !elasticLoadBalancers || !elasticLoadBalancersV2) return rcb();

            if (autoScalingGroups.err || !autoScalingGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for AutoScaling groups: ' +  helpers.addError(autoScalingGroups), region);
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
                helpers.addResult(results, 0, 'No AutoScaling group found', region);
                return rcb();
            }
            
            if (elasticLoadBalancers.data.length) {
                elasticLoadBalancers.data.forEach(function(elb) {
                    if(elb.LoadBalancerName) {
                        loadBalancers[elb.LoadBalancerName] =  elb;
                    }
                });
            }

            if (elasticLoadBalancersV2.data.length) {
                elasticLoadBalancersV2.data.forEach(function(elbv2) {
                    if(elbv2.LoadBalancerName) {
                        loadBalancers[elbv2.LoadBalancerName] =  elbv2;
                    }
                });
            }

            autoScalingGroups.data.forEach(function(asg) {
                var asgAvailabilityZones = asg.AvailabilityZones;
                var distinctAzs = [];
                var resource = asg.AutoScalingGroupARN;

                if(asg.HealthCheckType == 'ELB') {
                    if (asg.LoadBalancerNames && asg.LoadBalancerNames.length) {

                        asg.LoadBalancerNames.forEach(function(elbName) {
                            if(loadBalancers[elbName]) {
                                var loadBalancer = loadBalancers[elbName];
                                var elbAvailabilityZones = loadBalancer.AvailabilityZones;

                                if (elbAvailabilityZones && elbAvailabilityZones.length) {
                                    elbAvailabilityZones.forEach(function(elbAz) {
                                        if(asgAvailabilityZones && asgAvailabilityZones.length && !asgAvailabilityZones.includes(elbAz)) {
                                            distinctAzs.push(elbAz);
                                        }
                                    });
                                }

                                if(distinctAzs.length) {
                                    helpers.addResult(results, 2,
                                        'Auto scaling group "' + asg.AutoScalingGroupName + '" has load balancers in these different availability zones: ' + distinctAzs.join(', '),
                                        region, resource);
                                }
                                else {
                                    helpers.addResult(results, 0,
                                        'Auto scaling group "' + asg.AutoScalingGroupName + '" has all load balancers in same availability zones',
                                        region, resource);
                                }
                            } else {
                                helpers.addResult(results, 2,
                                    'AutoScaling group "' + asg.AutoScalingGroupName + '" utilizes inactive load balancers',
                                    region, resource);
                            }
                        });
                    }
                    else {
                        helpers.addResult(results, 0, 'AutoScaling group does not have any Load Balancer associated', region, resource);
                    }
                }
                else {
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
