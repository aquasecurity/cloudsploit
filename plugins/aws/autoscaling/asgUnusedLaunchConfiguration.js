var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Auto Scaling Unused Launch Configuration',
    category: 'AutoScaling',
    domain: 'Availability',
    description: 'Ensure that any unused Auto Scaling Launch Configuration templates are identified and removed from your account in order to adhere to AWS best practices.',
    more_info: 'A launch configuration is an instance configuration template that an Auto Scaling group uses to launch EC2 instances. When you create a launch configuration, you specify information for the instances. '+
        'Every unused Launch Configuration template should be removed for a better management of your AWS Auto Scaling components.',
    link: 'https://docs.aws.amazon.com/autoscaling/ec2/userguide/LaunchConfiguration.html',
    recommended_action: 'Identify and remove any Auto Scaling Launch Configuration templates that are not associated anymore with ASGs available in the selected AWS region.',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            var describeLaunchConfigurations = helpers.addSource(cache, source,
                ['autoscaling', 'describeLaunchConfigurations', region]);
    
            if (!describeLaunchConfigurations) return rcb();

            if (describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Auto Scaling launch configurations: ' + helpers.addError(describeLaunchConfigurations), region);
                return rcb();
            }

            if (!describeLaunchConfigurations.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling launch configurations found', region);
                return rcb();
            }

            if (!describeAutoScalingGroups || describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Auto Scaling groups: ' + helpers.addError(describeAutoScalingGroups), region);
                return rcb();
            }

            let usedLaunchConfig = [];
            describeAutoScalingGroups.data.forEach(group => {
                if (!group.LaunchConfigurationName) return;

                if (!usedLaunchConfig.includes(group.LaunchConfigurationName)) {
                    usedLaunchConfig.push(group.LaunchConfigurationName);
                }
            });

            describeLaunchConfigurations.data.forEach(config => {
                if (!config.LaunchConfigurationARN) return;

                if (config.LaunchConfigurationName && usedLaunchConfig.includes(config.LaunchConfigurationName)) {
                    helpers.addResult(results, 0,
                        `Auto Scaling launch configuration "${config.LaunchConfigurationName}" is being used`,
                        region, config.LaunchConfigurationARN);
                } else {
                    helpers.addResult(results, 2,
                        `Auto Scaling launch configuration "${config.LaunchConfigurationName}" is not being used`,
                        region, config.LaunchConfigurationARN);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
