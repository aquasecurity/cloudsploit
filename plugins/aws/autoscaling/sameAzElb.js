var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AutoScaling Group Missing ELB',
    category: 'AutoScaling',
    description: 'Ensures all autoscaling groups are referencing active load balancers.',
    more_info: 'Each autoscaling group should with a load balancer configured should reference an active ELB.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/attach-load-balancer-asg.html',
    recommended_action: 'Ensure that the autoscaling group load balancer has not been deleted. If so, remove it from the ASG.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'ELB:describeLoadBalancers'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

            if (!autoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No AutoScaling groups found', region);
                return rcb();
            }

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
                                    if(!asgAvailabilityZones.includes(elbAz)) {
                                        differentAzFound = true;
                                    }
                                });

                                if(differentAzFound) {
                                    helpers.addResult(results, 2, 'Load balancer "' + elbName + '" is not in the same AZ as of AutoScaling group', region, asgName);
                                }
                                else {
                                    helpers.addResult(results, 0, 'Load balancer "' + elbName + '" is in the same AZ as of AutoScaling group', region, asgName);
                                }
                            }
                        });
                    }
                    else {
                        helpers.addResult(results, 2, 'AutoScaling group does not have any Load Balancer associated', region, asgName);
                    }
                }
                else {
                    helpers.addResult(results, 0, 'AutoScaling group does not utilize a load balancer', region, asgName);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
