var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ASG Tag Propagation',
    category: 'AutoScaling',
    domain: 'Availability',
    severity: 'Medium',
    description: 'Ensures EC2 Auto Scaling Groups propagate tags to EC2 instances that it launches.',
    more_info: 'Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance. Tags should be propagated from an Auto Scaling group to the EC2 instances that it launches.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-tagging.html',
    recommended_action: 'Enable tag propagation for all tags on Auto Scaling Groups by setting PropagateAtLaunch to true for each tag.',
    apis: ['AutoScaling:describeAutoScalingGroups'],
    realtime_triggers: ['autoscaling:CreateAutoScalingGroup', 'autoscaling:UpdateAutoScalingGroup', 'autoscaling:CreateOrUpdateTags', 'autoscaling:DeleteTags'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for auto scaling groups: ' + 
                    helpers.addError(describeAutoScalingGroups), region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No auto scaling groups found', region);
                return rcb();
            }

            describeAutoScalingGroups.data.forEach(function(asg){
                var resource = asg.AutoScalingGroupARN;

                if (!resource) return;

                if (!asg.Tags || !asg.Tags.length) {
                    helpers.addResult(results, 0,
                        'Auto scaling group has no tags configured',
                        region, resource);
                    return;
                }

                var tagsNotPropagating = [];
                asg.Tags.forEach(function(tag) {
                    if (!tag.PropagateAtLaunch) {
                        tagsNotPropagating.push(tag.Key || 'unnamed');
                    }
                });

                 if (!tagsNotPropagating.length ) {
                    helpers.addResult(results, 0,
                        'Auto scaling group has all tags configured to propagate to EC2 instances',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Auto scaling group has ' + tagsNotPropagating.length + 
                        ' tag(s) not configured to propagate to EC2 instances',
                        region, resource);
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

