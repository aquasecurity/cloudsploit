var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Automate EBS Snapshot Lifecycle',
    category: 'EC2',
    description: 'Ensure DLM is used to automate EBS volume snapshots management.',
    more_info: 'Amazon Data Lifecycle Manager (DLM) service enables you to manage the lifecycle of EBS volume snapshots.\
            Using DLM helps in enforcing regular backup schedule, retaining backups, deleting outdated EBS snapshots',
    recommended_action: 'Create lifecycle policy for EBS volumes.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snapshot-lifecycle.html',
    apis: ['EC2:describeInstances', 'EC2:describeVolumes', 'DLM:getLifecyclePolicies',
        'DLM:getLifecyclePolicy', 'STS:getCallerIdentity'],

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
                    `Unable to describe EBS volumes: ${helpers.addError(describeVolumes)}`, region);
                return rcb();
            }

            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0,
                    'No EBS volumes found', region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    `Unable to EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            var getLifecyclePolicies = helpers.addSource(cache, source,
                ['dlm', 'getLifecyclePolicies', region]);

            if (!getLifecyclePolicies || getLifecyclePolicies.err | !getLifecyclePolicies.data) {
                helpers.addResult(results, 3,
                    `Unable to query DLM lifecycle policies: ${helpers.addError(getLifecyclePolicies)}`, region);
                return rcb();
            }

            var passingVolumes = [];
            var passingVolumeTags = {};
            var passingInstanceTags = {};
            getLifecyclePolicies.data.forEach(policy => {
                var getLifecyclePolicy = helpers.addSource(cache, source,
                    ['dlm', 'getLifecyclePolicy', region, policy.PolicyId]);

                if (!getLifecyclePolicy || getLifecyclePolicy.err || !getLifecyclePolicy.data || !getLifecyclePolicy.data.Policy) {
                    helpers.addResult(results, 3,
                        `Unable to query lifecycle policy: ${helpers.addError(getLifecyclePolicy)}`,
                        region, policy.PolicyId);
                    return;
                }

                if (getLifecyclePolicy.data.Policy.State &&
                    getLifecyclePolicy.data.Policy.State === 'ENABLED' &&
                    getLifecyclePolicy.data.Policy.PolicyDetails &&
                    getLifecyclePolicy.data.Policy.PolicyDetails.TargetTags &&
                    getLifecyclePolicy.data.Policy.PolicyDetails.TargetTags.length) {
                    if (getLifecyclePolicy.data.Policy.PolicyDetails.ResourceTypes &&
                        getLifecyclePolicy.data.Policy.PolicyDetails.ResourceTypes.length) {
                        if (getLifecyclePolicy.data.Policy.PolicyDetails.ResourceTypes.includes('VOLUME')) {
                            getLifecyclePolicy.data.Policy.PolicyDetails.TargetTags.forEach(tag => {
                                if (tag.Key && tag.Value) {
                                    if (passingVolumeTags[tag.Key]) passingVolumeTags[tag.Key].push(tag.Value); 
                                    else passingVolumeTags[tag.Key] = [tag.Value];
                                }
                            });
                        }

                        if (getLifecyclePolicy.data.Policy.PolicyDetails.ResourceTypes.includes('INSTANCE')) {
                            getLifecyclePolicy.data.Policy.PolicyDetails.TargetTags.forEach(tag => {
                                if (tag.Key && tag.Value) {
                                    if (passingInstanceTags[tag.Key]) passingInstanceTags[tag.Key].push(tag.Value); 
                                    else passingInstanceTags[tag.Key] = [tag.Value];
                                }
                            });
                        }
                    }
                }
            });

            if (describeInstances.data.length) {
                describeInstances.data.forEach(instance => {
                    if (instance.Instances && instance.Instances.length) {
                        instance.Instances.forEach(entry => {
                            if (entry.Tags && entry.Tags.length) {
                                for (var it in entry.Tags) {
                                    var itag = entry.Tags[it];

                                    if (passingInstanceTags[itag.Key] && passingInstanceTags[itag.Key].includes(itag.Value)) {
                                        if (entry.BlockDeviceMappings && entry.BlockDeviceMappings.length) {
                                            entry.BlockDeviceMappings.forEach(mapping => {
                                                if (mapping.Ebs && mapping.Ebs.VolumeId) passingVolumes.push(mapping.Ebs.VolumeId);
                                            });
                                        }
                                        break;
                                    }
                                }
                            }
                        });
                    } 
                });
            }

            async.each(describeVolumes.data, function(volume, vcb){
                if (!volume.VolumeId) return vcb();

                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:volume/${volume.VolumeId}`;
                var tagFound = false;

                if (passingVolumes.includes(volume.VolumeId)) tagFound = true;
                else if (volume.Tags && volume.Tags.length) {
                    for (var vt in volume.Tags) {
                        var vtag = volume.Tags[vt];
                        if (vtag.Key && vtag.Value &&
                            passingVolumeTags[vtag.Key] &&
                            passingVolumeTags[vtag.Key].includes(vtag.Value)) {
                            tagFound = true;
                            break;
                        }
                    }
                }

                if (tagFound) {
                    helpers.addResult(results, 0,
                        `EBS volume "${volume.VolumeId}" has lifecycle policy configured`, region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `EBS volume "${volume.VolumeId}" does not have lifecycle policy configured`, region, resource);
                }

                vcb();
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
