var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Encrypted Snapshots',
    category: 'EC2',
    description: 'Ensures EBS snapshots are encrypted at rest',
    more_info: 'EBS snapshots should have at-rest encryption enabled through AWS using KMS. If the volume was not encrypted and a snapshot was taken the snapshot will be unencrypted.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSSnapshots.html#encryption-support',
    recommended_action: 'Configure volume encryption and delete unencrypted EBS snapshots.',
    apis: ['EC2:describeSnapshots'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'EBS is a HIPAA-compliant solution that provides automated encryption ' +
                'of EC2 instance data at rest, but volumes must be configured to use ' +
                'encryption so their snapshots are also encrypted.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeSnapshots = helpers.addSource(cache, source,
                ['ec2', 'describeSnapshots', region]);

            if (!describeSnapshots) return rcb();

            if (describeSnapshots.err || !describeSnapshots.data) {
                helpers.addResult(results, 3,
                    'Unable to query for EBS Snapshots: ' + helpers.addError(describeSnapshots), region);
                return rcb();
            }

            if (!describeSnapshots.data.length) {
                helpers.addResult(results, 0, 'No EBS snapshots present', region);
                return rcb();
            }

            var unencryptedSnapshots = [];

            describeSnapshots.data.forEach(function(snapshot){
                if (!snapshot.Encrypted){
                    // arn:aws:ec2:region:account-id:snapshot/snapshot-id
                    var arn = 'arn:aws:ec2:' + region + ':' + snapshot.OwnerId + ':snapshot/' + snapshot.SnapshotId;
                    unencryptedSnapshots.push(arn);
                }
            });

            if (unencryptedSnapshots.length > 20) {
                helpers.addResult(results, 2, 'More than 20 EBS snapshots are unencrypted', region);
            } else if (unencryptedSnapshots.length) {
                for (var u in unencryptedSnapshots) {
                    helpers.addResult(results, 2, 'EBS snapshot is unencrypted', region, unencryptedSnapshots[u]);
                }
            } else {
                helpers.addResult(results, 0, 'No unencrypted snapshots found', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
