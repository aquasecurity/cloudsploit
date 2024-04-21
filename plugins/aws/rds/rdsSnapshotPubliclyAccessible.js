var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Snapshot Publicly Accessible',
    category: 'RDS',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that Amazon RDS database snapshots are not publicly exposed.',
    more_info: 'If an RDS snapshot is exposed to the public, any AWS account can copy the snapshot and create a new database instance from it. ' +
        'It is a best practice to ensure RDS snapshots are not exposed to the public to avoid any accidental leak of sensitive information.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html',
    recommended_action: 'Ensure Amazon RDS database snapshot is not publicly accessible and available for any AWS account to copy or restore it.',
    apis: ['RDS:describeDBSnapshots', 'RDS:describeDBSnapshotAttributes'],
    realtime_triggers: ['rds:CreateDBSnapshot', 'rds:ModifyDBSnapshotAttribute','rds:DeleteDBSnapshot'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb){
            var describeDBSnapshots = helpers.addSource(cache, source,
                ['rds', 'describeDBSnapshots', region]);

            if (!describeDBSnapshots) return rcb();

            if (describeDBSnapshots.err || !describeDBSnapshots.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS snapshots: ' + helpers.addError(describeDBSnapshots), region);
                return rcb();
            }

            if (!describeDBSnapshots.data.length) {
                helpers.addResult(results, 0, 'No RDS snapshots found', region);
                return rcb();
            }

            describeDBSnapshots.data.forEach(snapshot => {
                if (!snapshot.DBSnapshotIdentifier) return;

                var snapshotIdentifier = snapshot.DBSnapshotIdentifier;
                var resource = snapshot.DBSnapshotArn;

                var describeDBSnapshotAttributes = helpers.addSource(cache, settings,
                    ['rds', 'describeDBSnapshotAttributes', region, snapshotIdentifier]);

                if (!describeDBSnapshotAttributes ||
                    describeDBSnapshotAttributes.err ||
                    !describeDBSnapshotAttributes.data ||
                    !describeDBSnapshotAttributes.data.DBSnapshotAttributesResult) {
                    helpers.addResult(results, 3,
                        `Unable to describe Snapshot attributes "${snapshotIdentifier}": ${helpers.addError(describeDBSnapshotAttributes)}`,
                        region, resource);

                    return;
                }

                let publicSnapshot;
                if (describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes) {
                    publicSnapshot = describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes.find(
                        attribute => attribute.AttributeValues && attribute.AttributeValues.includes('all')
                    );
                }

                if (publicSnapshot){
                    helpers.addResult(results, 2,
                        'RDS Snapshot is publicly exposed',
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'RDS Snapshot is not publicly exposed',
                        region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
