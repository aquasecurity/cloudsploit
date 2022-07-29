var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EBS Encrypted Snapshots',
    category: 'EC2',
    domain: 'Compute',
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

            describeSnapshots.data.forEach(function(snapshot){
                var arn = 'arn:aws:ec2:' + region + ':' + snapshot.OwnerId + ':snapshot/' + snapshot.SnapshotId;
                if (snapshot.Encrypted){
                    helpers.addResult(results, 0, 'EBS snapshot is encrypted', region, arn);
                } else {
                    helpers.addResult(results, 2, 'EBS snapshot is unencrypted', region, arn);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
