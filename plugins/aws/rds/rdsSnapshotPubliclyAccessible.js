var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Snapshot Publicly Accessible',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure RDS snapshot is not public.',
    more_info: 'If an RDS snapshot is exposed to the public, any AWS account can copy the snapshot and create a new database instance from it. It is a best practice to ensure RDS snapshots are not exposed to the public to avoid any accidental leak of sensitive information.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html',
    recommended_action: 'Ensure Amazon RDS database snapshot is not publicly accessible and available for any AWS account to copy or restore it.',
    apis: ['RDS:describeDBSnapshots', 'RDS:describeDBSnapshotAttributes'],

    run: function(cache, settings, callback) {
        // console.log(JSON.stringify(cache, null, 2));
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

            async.each(describeDBSnapshots.data, function(snapshot, ccb){
                if (!snapshot.DBSnapshotIdentifier) return ccb();

                var snapshotIdentifier = snapshot.DBSnapshotIdentifier;
                var resource = snapshot.DBSnapshotArn;

                var describeDBSnapshotAttributes = helpers.addSource(cache, settings,
                    ['rds', 'describeDBSnapshotAttributes', region, snapshotIdentifier]);
                    // console.log(describeDBSnapshotAttributes);

                if (!describeDBSnapshotAttributes ||
                    describeDBSnapshotAttributes.err ||
                    !describeDBSnapshotAttributes.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe Snapshot attributes "${snapshotIdentifier}": ${helpers.addError(describeDBSnapshotAttributes)}`,
                        region, resource);
                } else if (describeDBSnapshotAttributes.data.DBSnapshotAttributesResult &&
                        describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes) {
                        for (let attribute of describeDBSnapshotAttributes.data.DBSnapshotAttributesResult.DBSnapshotAttributes){
                            if (attribute.AttributeValues.includes("all")){
                            helpers.addResult(results, 2,
                                `RDS Snapshot is publicly accessible`,
                                region, resource);
                            } else {
                                helpers.addResult(results, 0,
                                    `RDS Snapshot is not publicly accessible`,
                                    region, resource);
                            }
                        }
                } 

                ccb();
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
