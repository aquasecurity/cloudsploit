var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Outdated Amazon Machine Images',
    category: 'EC2',
    description: 'Ensures that deprecated Amazon Machine Images are not in use.',
    more_info: 'Deprecated Amazon Machine Images should not be used to make an instance.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html',
    recommended_action: 'Delete the instances using deprecated AMIs',
    apis: ['EC2:describeImages', 'EC2:describeInstances', 'AutoScaling:describeLaunchConfigurations',
        'EC2:describeLaunchTemplates', 'EC2:describeLaunchTemplateVersions','STS:getCallerIdentity'],
    settings: {
        check_ami_usage: {
            name: 'Check for Deprecated AMI Usage',
            description: 'When set to true all instances are checked to see if deprecated AMIs are being used',
            regex: '^(true|false)$',
            default: 'true'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            check_ami_usage: settings.check_ami_usage || this.settings.check_ami_usage.default
        };

        config.check_ami_usage = (config.check_ami_usage == 'true');
        
        const results = [];
        const source = {};
        
        if (!config.check_ami_usage) return callback(null, results, source);
        
        const regions = helpers.regions(settings);
        const acctRegion = helpers.defaultRegion(settings);
        const awsOrGov = helpers.defaultPartition(settings);
        const accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            const describeImages = helpers.addSource(cache, source,
                ['ec2', 'describeImages', region]);

            if (!describeImages) return rcb();

            if (describeImages.err || !describeImages.data) {
                helpers.addResult(results, 3,
                    `Unable to query for AMIs: ${helpers.addError(describeImages)}`,
                    region);
                return rcb();
            }

            if (!describeImages.data.length) {
                helpers.addResult(results, 0,
                    'No Amazon Machine Images found', region);
                return rcb();
            }

            const describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            const describeLaunchConfigurations = helpers.addSource(cache, source,
                ['autoscaling', 'describeLaunchConfigurations', region]);
            
            const describeLaunchTemplates = helpers.addSource(cache, source,
                ['ec2', 'describeLaunchTemplates', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to query EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            
            if (!describeLaunchConfigurations || describeLaunchConfigurations.err || !describeLaunchConfigurations.data) {
                helpers.addResult(results, 3,
                    `Unable to query Auto Scaling launch configurations: ${helpers.addError(describeLaunchConfigurations)}`, region);
                return rcb();
            }

            if (!describeLaunchTemplates || describeLaunchTemplates.err || !describeLaunchTemplates.data) {
                helpers.addResult(results, 3,
                    `Unable to query EC2 launch templates: ${helpers.addError(describeLaunchTemplates)}`, region);
                return rcb();
            }

            let found = false;
            describeImages.data.forEach(image => {
                const currentDate = new Date();
                if (image.DeprecationTime && new Date(image.DeprecationTime) < currentDate) {                    
                    found = true;                   
                    let usedAmi = false;
                    if (describeInstances.data.length) {
                        describeInstances.data.forEach(instance => {
                            if (instance.Instances && instance.Instances.length) {
                                instance.Instances.forEach(element => {
                                    if (element.ImageId && image.ImageId == element.ImageId) usedAmi = true;
                                });
                            }
                        });
                    }
        
                    if (!usedAmi && describeLaunchConfigurations.data.length) {
                        describeLaunchConfigurations.data.forEach(config => {
                            if (config.ImageId && image.ImageId == config.ImageId) usedAmi = true;
                        });
                    }

                    if (!usedAmi && describeLaunchTemplates.data.length) {
                        describeLaunchTemplates.data.forEach(template=>{
                            var describeLaunchTemplateVersions = helpers.addSource(cache, source,
                                ['ec2', 'describeLaunchTemplateVersions', region, template.LaunchTemplateId]);

                            if (describeLaunchTemplateVersions &&
                                describeLaunchTemplateVersions.data &&
                                describeLaunchTemplateVersions.data.LaunchTemplateVersions) {
                                let templateVersion = describeLaunchTemplateVersions.data.LaunchTemplateVersions.find(version => version.VersionNumber == template.DefaultVersionNumber);
                                if (templateVersion && templateVersion.LaunchTemplateData && templateVersion.LaunchTemplateData.ImageId) usedAmi = true;
                                
                            }
                        });
                    }
                    
                    const resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:image/${image.ImageId}`;
                    const status = usedAmi ? 2: 0; 
                    helpers.addResult(results, status,
                        `Deprecated Amazon Machine Image "${image.ImageId}" is ${usedAmi ? '': 'not '}in use`,
                        region, resource);
                }
            });

            if (!found) {
                helpers.addResult(results, 0,
                    'No deprecated Amazon Machine Image found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
