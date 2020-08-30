var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling Group Missing ELB',
    category: 'AutoScaling',
<<<<<<< HEAD
    description: 'Ensures all autoscaling groups are referencing active load balancers.',
    more_info: 'Each autoscaling group should with a load balancer configured should reference an active ELB.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Ensure that the autoscaling group load balancer has not been deleted. If so, remove it from the ASG.',
<<<<<<< HEAD
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers'],
=======
=======
    description: 'Ensures all autoscaling groups with attached ELBs are operating in the same availability zone.',
    more_info: 'To work properly and prevent orphaned instances, ELBs must be created in the same availability zones as the backend instances in the autoscaling group.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-add-availability-zone.html',
    recommended_action: 'Update the ELB to use the same availability zones as the autoscaling group.',
>>>>>>> 89a3f78... Updated sameAzElb plugin
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers', 'ELBv2:describeLoadBalancers'],
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call

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
<<<<<<< HEAD

            if (!autoScalingGroups || !elasticLoadBalancers) return rcb();

=======

            var elasticLoadBalancersV2 = helpers.addSource(cache, source,
                ['elbv2', 'describeLoadBalancers', region]);

            if (!autoScalingGroups || !elasticLoadBalancers || !elasticLoadBalancersV2) return rcb();
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call

            if (autoScalingGroups.err || !autoScalingGroups.data) {
                helpers.addResult(results, 3, 'Unable to query for AutoScaling groups: ' +  helpers.addError(autoScalingGroups), region);
                return rcb();
            }

            if (elasticLoadBalancers.err || !elasticLoadBalancers.data) {
<<<<<<< HEAD
                helpers.addResult(results, 3, 'Unable to query for load balancers: ' +  helpers.addError(elasticLoadBalancers), region);
=======
                helpers.addResult(results, 3, 'Unable to query for Classic load balancers: ' +  helpers.addError(elasticLoadBalancers), region);
                return rcb();
            }

            if (elasticLoadBalancersV2.err || !elasticLoadBalancersV2.data) {
                helpers.addResult(results, 3, 'Unable to query for Application/Network load balancers: ' +  helpers.addError(elasticLoadBalancersV2), region);
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call
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

<<<<<<< HEAD
            autoScalingGroups.data.forEach(function(asg){
                var asgAvailabilityZones = asg.AvailabilityZones;
                var asgName = asg.AutoScalingGroupName;
                var differentAzFound = false;

                if(asg.HealthCheckType == 'ELB') {
                    if (asg.LoadBalancerNames && asg.LoadBalancerNames.length) {

                        if (!elasticLoadBalancers.data.length) {
                            helpers.addResult(results, 2, 'No load balancers found', region);
                            return rcb();
                        }

                        elasticLoadBalancers.data.forEach(function(elb) {
                            var elbName = elb.LoadBalancerName;

                            if(asg.LoadBalancerNames.includes(elb.LoadBalancerName)){
                                differentAzFound = false;
                                var elbAvailabilityZones = elb.AvailabilityZones;

                                //if Load Balancer is in any AZ different from AutoScaling group's AZs then mark ELB as different
                                elbAvailabilityZones.forEach(function(elbAz){
=======
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
                            if(elbName in loadBalancers) {
                                var loadBalancer = loadBalancers[elbName];
                                var elbAvailabilityZones = loadBalancer.AvailabilityZones;

                                // if Load Balancer is in any AZ different from AutoScaling group's AZs then add an error result
                                elbAvailabilityZones.forEach(function(elbAz) {
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call
                                    if(!asgAvailabilityZones.includes(elbAz)) {
                                        distinctAzs.push(elbAz);
                                    }
                                });

<<<<<<< HEAD
                                if(differentAzFound) {
<<<<<<< HEAD
                                    helpers.addResult(results, 2, 'Load balancer "' + elbName + '" is not in the same AZ as of AutoScaling group', region, asgName);
                                }
                                else {
                                    helpers.addResult(results, 0, 'Load balancer "' + elbName + '" is in the same AZ as of AutoScaling group', region, asgName);
=======
                                    helpers.addResult(results, 2, 'Load balancer "' + elbName + '" is not in the same AZ as of AutoScaling group', region, resource);
                                }
                                else {
                                    helpers.addResult(results, 0, 'Load balancer "' + elbName + '" is in the same AZ as of AutoScaling group', region, resource);
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call
=======
                                if(distinctAzs.length) {
                                    helpers.addResult(results, 2,
                                        'Auto scaling group "' + asg.AutoScalingGroupName + '" has these load balancers in different AZs: ' + distinctAzs.join(', '),
                                    region, resource);
                                }
                                else {
                                    helpers.addResult(results, 0,
                                        'Auto scaling group "' + asg.AutoScalingGroupName + '" has all load balancers in same AZ',
                                    region, resource);
>>>>>>> 89a3f78... Updated sameAzElb plugin
                                }
                            }
                            else {
                                helpers.addResult(results, 2, 'AutoScaling group utilizes an inactive load balancer "'+ elbName + '"', region, resource);
                            }
                        });
                    }
                    else {
<<<<<<< HEAD
                        helpers.addResult(results, 2, 'AutoScaling group does not have any Load Balancer associated', region, asgName);
                    }
                }
                else {
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, asgName);
=======
                        helpers.addResult(results, 2, 'AutoScaling group does not have any Load Balancer associated', region, resource);
                    }
                }
                else {
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, resource);
>>>>>>> 9c56541... Feature/43: Updated describeLoadBalancers api call
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
