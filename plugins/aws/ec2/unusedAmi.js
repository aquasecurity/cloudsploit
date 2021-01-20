var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Unused Amazon Machine Images',
    category: 'EC2',
    description: 'Ensures that all Amazon Machine Images are in use to ensure cost optimization.',
    more_info: 'All unused/deregistered Amazon Machine Images should be deleted to avoid extraneous cost.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html',
    recommended_action: 'Delete the unused/deregistered AMIs',
    apis: ['EC2:describeImages', 'EC2:describeInstances', 'AutoScaling:describeLaunchConfigurations', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var usedAmis = [];

        async.each(regions.ec2, function(region, rcb){
            var describeImages = helpers.addSource(cache, source,
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

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            var describeLaunchConfigurations = helpers.addSource(cache, source,
                ['autoscaling', 'describeLaunchConfigurations', region]);

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

            if (describeInstances.data.length) {
                describeInstances.data.forEach(instance => {
                    if (instance.Instances && instance.Instances.length) {
                        instance.Instances.forEach(element => {
                            if(element.ImageId && !usedAmis.includes(element.ImageId)) {
                                usedAmis.push(element.ImageId);
                            }
                        });
                    }
                });
            }

            if (describeLaunchConfigurations.data.length) {
                describeLaunchConfigurations.data.forEach(config => {
                    if(config.ImageId && !usedAmis.includes(config.ImageId)) {
                        usedAmis.push(config.ImageId);
                    }
                });
            }

            describeImages.data.forEach(image => {
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:image/${image.ImageId}`;

                if (usedAmis.includes(image.ImageId)) {
                    helpers.addResult(results, 0,
                        `Amazon Machine Image "${image.ImageId}" is in use`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Amazon Machine Image "${image.ImageId}" is not in use`,
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
