var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volumes Too Old Snapshots',
    category: 'EC2',
    description: 'Ensure that EBS volume snapshots are deleted after defined time period.',
    more_info: 'EBS volume snapshots older than indicated should be deleted after defined time period for cost optimization.',
    link: 'https://docs.amazonaws.cn/en_us/AWSEC2/latest/UserGuide/ebs-deleting-snapshot.html',
    recommended_action: 'Delete the EBS snapshots past their defined expiration date',
    apis: ['EC2:describeSnapshots'],
    settings: {
        ebs_snapshot_life: {
            name: 'EBS Snapshot Life',
            description: 'Return a failing result when snapshot creation date is before this number of days in the past',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 30
        },
        ebs_result_limit: {
            name: 'EBS Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: 20,
        },
    },

    run: function(cache, settings, callback) {
        var config = {
            ebs_snapshot_life: settings.ebs_snapshot_life || this.settings.ebs_snapshot_life.default,
            ebs_result_limit: settings.ebs_result_limit || this.settings.ebs_result_limit.default
        };

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeSnapshots = helpers.addSource(cache, source,
                ['ec2', 'describeSnapshots', region]);

            if (!describeSnapshots) return rcb();

            if (describeSnapshots.err || !describeSnapshots.data) {
                helpers.addResult(results, 3,
                    `Unable to query for EBS Snapshots: ${helpers.addError(describeSnapshots)}`, region);
                return rcb();
            }

            if (!describeSnapshots.data.length) {
                helpers.addResult(results, 0, 'No EBS snapshots present', region);
                return rcb();
            }

            var now = new Date();
            var oldSnapshots = [];
            describeSnapshots.data.forEach(snapshot => {
                if (!snapshot.SnapshotId) return;

                var resource = `arn:${awsOrGov}:${region}:${snapshot.OwnerId}:snapshot/${snapshot.SnapshotId}`;
                var then = new Date(snapshot.StartTime);
                var difference = helpers.daysBetween(then, now);

                if (Math.abs(difference) > config.ebs_snapshot_life) {
                    oldSnapshots.push(resource);
                }
            });

            if (oldSnapshots.length > config.ebs_result_limit) {
                helpers.addResult(results, 2,
                    `More than ${config.ebs_result_limit} EBS snapshots are too old`, region);
            } else if (oldSnapshots.length) {
                for (var o in oldSnapshots) {
                    helpers.addResult(results, 2,
                        `EBS snapshot is more than ${config.ebs_snapshot_life} days old`, region, oldSnapshots[o]);
                }
            } else {
                helpers.addResult(results, 0,
                    'No old EBS snapshots found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
