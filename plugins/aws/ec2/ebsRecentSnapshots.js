var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Volumes Recent Snapshots',
    category: 'EC2',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that EBS volume has had a recent snapshot within the configured time period',
    more_info: 'EBS volumes without recent snapshots may be at risk of data loss or recovery issues.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html',
    recommended_action: 'Create a new snapshot for EBS volume within the configured time period.',
    apis: ['EC2:describeSnapshots','STS:getCallerIdentity'],
    settings: {
        ebs_recent_snapshot_days: {
            name: 'EBS Recent Snapshot Days',
            description: 'Number of days to consider a snapshot as recent. Snapshots older than this will be flagged as FAIL.',
            regex: '^[1-9]{1}[0-9]{0,2}$',
            default: '7'
        }
    },
    realtime_triggers: ['ec2:CreateSnapshot', 'ec2:DeleteSnapshot'],

    run: function(cache, settings, callback) {
        var config = {
            ebs_recent_snapshot_days: parseInt(settings.ebs_recent_snapshot_days || this.settings.ebs_recent_snapshot_days.default)
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
            
            var today = new Date();
            describeSnapshots.data.forEach(snapshot => {
                if (!snapshot.SnapshotId) return;

                var resource = `arn:${awsOrGov}:${region}:${snapshot.OwnerId}:snapshot/${snapshot.SnapshotId}`;
                var snapshotTime = new Date(snapshot.StartTime);
                var difference = Math.floor((today -snapshotTime) / (1000 * 60 * 60 * 24));

                if (difference > config.ebs_recent_snapshot_days){
                    helpers.addResult(results, 2, 
                        'EBS volume does not have a recent snapshot', region,resource);
                } else {
                    helpers.addResult(results, 0, 
                        'EBS volume has a recent snapshot', region,resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

