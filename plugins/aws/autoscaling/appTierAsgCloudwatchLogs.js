var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier Auto Scaling Group CloudWatch Logs Enabled',
    category: 'AutoScaling',
    description: 'Ensures that App-Tier Auto Scaling Groups are using CloudWatch logs agent.',
    more_info: 'EC2 instance available within app-tier Auto Scaling Group (ASG) should use an AWS CloudWatch Logs agent to monitor, store and access log files.',
    link: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Install-CloudWatch-Agent.html',
    recommended_action: 'Update app-tier Auto Scaling Group to use CloudWatch Logs agent',
    apis: ['AutoScaling:describeAutoScalingGroups', 'AutoScaling:describeLaunchConfigurations', 'STS:getCallerIdentity'],
    settings: {
        app_tier_tag_key: {
            name: 'Auto Scaling App-Tier Tag Key',
            description: 'App-Tier tag key used by Auto Scaling groups to indicate App-Tier groups',
            regex: '^.*$',
            default: ''
        },
        cw_log_agent_install_command: {
            name: 'Cloudwatch Agent Install Command',
            description: 'Commands to install CloudWatch agent',
            regex: '^.*$',
            default: '#!/bin/bash curl https://s3.amazonaws.com//aws-cloudwatch/downloads/latest/awslogs-agent-setup.py -O ' +
            'chmod +x ./awslogs-agent-setup.py ' +
            './awslogs-agent-setup.py -n -r <AWS_REGION> -c <S3_CLOUDWATCH_AGENT_CONFIG_FILE_LOCATION>'
        },
        s3_cw_agent_config_file: {
            name: 'S3 Cloudwatch Agent Config File Location',
            description: 'S3 path of cloudwatch agent configuration file',
            regex: '^.*$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            app_tier_tag_key: settings.app_tier_tag_key || this.settings.app_tier_tag_key.default,
            cw_log_agent_install_command: settings.cw_log_agent_install_command || this.settings.cw_log_agent_install_command.default,
            s3_cw_agent_config_file: settings.s3_cw_agent_config_file || this.settings.s3_cw_agent_config_file.default
        };

        if (!config.app_tier_tag_key.length) return callback();

        async.each(regions.autoscaling, function(region, rcb){
            var describeAutoScalingGroups = helpers.addSource(cache, source,
                ['autoscaling', 'describeAutoScalingGroups', region]);

            if (!describeAutoScalingGroups) return rcb();

            if (describeAutoScalingGroups.err || !describeAutoScalingGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Auto Scaling groups: ${helpers.addError(describeAutoScalingGroups)}`,
                    region);
                return rcb();
            }

            if (!describeAutoScalingGroups.data.length) {
                helpers.addResult(results, 0, 'No Auto Scaling groups found', region);
                return rcb();
            }

            var appTierAsgFound = false;
            async.each(describeAutoScalingGroups.data, function(asg, cb){

                var appTierTag = false;
                if(asg.Tags && asg.Tags.length){
                    for (var t in asg.Tags) {
                        var tag = asg.Tags[t];
                        if(tag && tag.Key && tag.Key === config.app_tier_tag_key) {
                            appTierTag = true;
                            appTierAsgFound = true;
                            break;
                        }
                    }
                }

                if (appTierTag) {
                    var resource = asg.AutoScalingGroupARN;

                    var describeLaunchConfigurations = helpers.addSource(cache, source,
                        ['autoscaling', 'describeLaunchConfigurations', region, asg.AutoScalingGroupARN]);

                    if(!describeLaunchConfigurations ||
                        describeLaunchConfigurations.err ||
                        !describeLaunchConfigurations.data ||
                        !describeLaunchConfigurations.data.LaunchConfigurations ||
                        !describeLaunchConfigurations.data.LaunchConfigurations.length) {
                        helpers.addResult(results, 3,
                            `Unable to query launch configurations for auto scaling group "${asg.AutoScalingGroupName}": ${helpers.addError(describeLaunchConfigurations)}`,
                            region, resource);
                        return cb();
                    }

                    var logsEnabled = false;                    
                    describeLaunchConfigurations.data.LaunchConfigurations.forEach(function(launchConfig){
                        
                        config.cw_log_agent_install_command = config.cw_log_agent_install_command.replace('<AWS_REGION>', region);
                        config.cw_log_agent_install_command = config.cw_log_agent_install_command.replace('<S3_CLOUDWATCH_AGENT_CONFIG_FILE_LOCATION>', config.s3_cw_agent_config_file);
                        if(launchConfig.UserData &&
                            launchConfig.UserData.indexOf(config.cw_log_agent_install_command) > -1) {
                            logsEnabled = true;
                        }
                    });

                    if (logsEnabled) {
                        helpers.addResult(results, 0,
                            `Auto Scaling group "${asg.AutoScalingGroupName}" is using CloudWatch Logs agent`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Auto Scaling group "${asg.AutoScalingGroupName}" is not using Clouwatch Logs agent`,
                            region, resource);
                    }
                }

                if (!appTierAsgFound) {
                    helpers.addResult(results, 0,
                        'No App-Tier Auto Scaling groups found', region);
                }
                cb();
            }, function(){
                rcb();
            });

        }, function(){
            callback(null, results, source);
        });

    }
}; 