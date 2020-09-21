var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Suspended AutoScaling Groups',
    category: 'AutoScaling',
    description: 'Ensures that there are no Amazon AutoScaling groups with suspended processes.',
    more_info: 'AutoScaling groups should not have any suspended processes to avoid disrupting the AutoScaling workflow.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html',
    recommended_action: 'Update the AutoScaling group to resume the suspended processes.',
    apis: ['AutoScaling:describeAutoScalingGroups'],

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
                    `Unable to query for AutoScaling groups: ${helpers.addError(describeAutoScalingGroups)}`, region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No AutoScaling groups found', region);
                return rcb();
            }

            describeAutoScalingGroups.data.forEach(function(asg){
                if (!asg.SuspendedProcesses || !asg.SuspendedProcesses.length) {
                    helpers.addResult(results, 0,
                        `AutoScaling group "${asg.AutoScalingGroupName}" does not have any suspended processes`,
                        region, asg.AutoScalingGroupARN);
                }
                else {
                    var suspendedProcesses = [];
                    asg.SuspendedProcesses.forEach(function(process) {
                        suspendedProcesses.push(process.ProcessName);
                    });

                    helpers.addResult(results, 2,
                        `AutoScaling group "${asg.AutoScalingGroupName}" has these suspended processes: ${suspendedProcesses.join(', ')}`,
                        region, asg.AutoScalingGroupARN);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
