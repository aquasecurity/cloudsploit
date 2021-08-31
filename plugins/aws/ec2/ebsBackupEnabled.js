var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Backup Enabled',
    category: 'EC2',
    description: 'Checks whether EBS Backup is enabled',
    more_info: 'EBS volumes should have backups in the form of snapshots.',
    recommended_action: 'Ensure that each EBS volumes contain at least .',
    link: 'https://docs.aws.amazon.com/prescriptive-guidance/latest/backup-recovery/new-ebs-volume-backups.html',
    apis: ['EC2:describeVolumes', 'EC2:describeSnapshots', 'EC2:describeInstances', 'STS:getCallerIdentity'],
    settings: {
        ignore_spot_instance_volumes: {
            name: 'Ignore Spot Instance Volumes',
            description: 'Ignore volumes which are attached to spot instances',
            regex: '^(true|false)$',
            default: 'true'
        }
    },

    run: function(cache, settings, callback) {
        let results = [];
        let source = {};
        let regions = helpers.regions(settings);

        let config = {
            ignore_spot_instance_volumes: settings.ignore_spot_instance_volumes || this.settings.ignore_spot_instance_volumes.default
        };

        let ignoreSpot = (config.ignore_spot_instance_volumes == 'true');

        let acctRegion = helpers.defaultRegion(settings);
        let awsOrGov = helpers.defaultPartition(settings);
        let accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb) {
            let describeVolumes = helpers.addSource(cache, source,
                ['ec2', 'describeVolumes', region]);
            let describeSnapshots = helpers.addSource(cache, source,
                ['ec2', 'describeSnapshots', region]);

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

            if (!describeSnapshots || describeSnapshots.err || !describeSnapshots.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EBS Snapshots: ${helpers.addError(describeSnapshots)}`, region);
                return rcb();
            }

            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances || describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for instances: ' + helpers.addError(describeInstances), region);
                return rcb();
            }

            let volumeSet = new Set();
            let spotInstances = [];

            if (ignoreSpot) {
                for (var instance of describeInstances.data) {
                    for (var entry of instance.Instances) {
                        if (entry.InstanceId &&
                            entry.InstanceLifecycle &&
                            entry.InstanceLifecycle.toLowerCase() == 'spot') spotInstances.push(entry.InstanceId);
                    }
                }
            }

            describeSnapshots.data.forEach(function(snapshot){
                if (snapshot.VolumeId) {
                    volumeSet.add(snapshot.VolumeId);
                }
            });

            describeVolumes.data.forEach(function(volume) {
                let volumeArn = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;
                if (volume.VolumeId) {
                    if (ignoreSpot && volume.Attachments && volume.Attachments.length) {
                        let found = volume.Attachments.find(attachment => attachment.InstanceId && !spotInstances.includes(attachment.InstanceId));
                        if (!found) return;
                    }

                    if (volumeSet.has(volume.VolumeId)) {
                        helpers.addResult(results, 0,
                            'EBS Volume is backed up',
                            region, volumeArn);
                    } else {
                        helpers.addResult(results, 2,
                            'EBS Volume is not backed up',
                            region, volumeArn);
                    }
                }
            });
            rcb();

        }, function() {
            callback(null, results, source);
        });
    }
};
