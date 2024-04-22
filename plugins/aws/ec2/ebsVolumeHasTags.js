var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volume has tags',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Low',
    description: 'Ensure that EBS Volumes have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify EBS volumes and add tags',
    link: 'https://aws.amazon.com/blogs/aws/new-tag-ec2-instances-ebs-volumes-on-creation/',
    apis: ['EC2:describeVolumes', 'STS:getCallerIdentity'],
    realtime_triggers: ['ec2:CreateVolume', 'ec2:AddTags', 'ec2:DeleteTags','ec2:DeleteVolume'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb) {
            var describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);

            if (!describeVolumes) return rcb();

            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EBS Volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS Volumes found', region);
                return rcb();
            }

            for (let volume of describeVolumes.data) {
                if (!volume.VolumeId) continue;

                var volumeArn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;

                if (!volume.Tags || !volume.Tags.length) {
                    helpers.addResult(results, 2, 'EBS volume does not have tags', region, volumeArn);
                } else {
                    helpers.addResult(results, 0, 'EBS volume has tags', region, volumeArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};