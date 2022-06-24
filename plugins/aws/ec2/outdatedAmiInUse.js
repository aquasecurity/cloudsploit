var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Outdated Amazon Machine Images',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures that deprecated Amazon Machine Images are not in use.',
    more_info: 'Deprecated Amazon Machine Images should not be used to make an instance.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ami-deprecate.html',
    recommended_action: 'Delete the instances using deprecated AMIs',
    apis: ['EC2:describeImages', 'EC2:describeInstances', 'AutoScaling:describeLaunchConfigurations',
        'EC2:describeLaunchTemplates', 'EC2:describeLaunchTemplateVersions','STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        
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
                if (!image.ImageId) return;

                if (image.DeprecationTime && new Date(image.DeprecationTime) < new Date()) {                    
                    found = true;
                    let amiInUse = false;

                    if (describeInstances.data.length) {
                        for (const instance of describeInstances.data) {
                            if (instance.Instances && instance.Instances.length) {
                                for (const element of instance.Instances) {
                                    if (element.ImageId && image.ImageId == element.ImageId) {
                                        amiInUse = true;
                                        break;
                                    }
                                }
                            }
                            if (amiInUse) break;
                        }
                    }
        
                    if (!amiInUse && describeLaunchConfigurations.data.length) {
                        for (const config of describeLaunchConfigurations.data) {
                            if (config.ImageId && image.ImageId == config.ImageId) {
                                amiInUse = true;
                                break;
                            }
                        }
                    }

                    if (!amiInUse && describeLaunchTemplates.data.length) {
                        for (const template of describeLaunchConfigurations.data) {
                            if (template.LaunchTemplateDId) {
                                var describeLaunchTemplateVersions = helpers.addSource(cache, source,
                                    ['ec2', 'describeLaunchTemplateVersions', region, template.LaunchTemplateId]);
    
                                if (template.DefaultVersionNumber &&
                                    describeLaunchTemplateVersions &&
                                    describeLaunchTemplateVersions.data &&
                                    describeLaunchTemplateVersions.data.LaunchTemplateVersions) {
                                    let templateVersion = describeLaunchTemplateVersions.data.LaunchTemplateVersions.find(version => version.VersionNumber == template.DefaultVersionNumber);
                                    if (templateVersion && templateVersion.LaunchTemplateData && templateVersion.LaunchTemplateData.ImageId &&
                                        image.ImageId == templateVersion.LaunchTemplateData.ImageId) {
                                        amiInUse = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    
                    const resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:image/${image.ImageId}`;
                    const status = amiInUse ? 2: 0; 
                    helpers.addResult(results, status,
                        `Deprecated Amazon Machine Image "${image.ImageId}" is ${amiInUse ? '': 'not '}in use`,
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
