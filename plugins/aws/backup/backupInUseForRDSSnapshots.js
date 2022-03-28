var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Backup In Use For RDS Snapshots',
    category: 'Backup',
    domain: 'Storage',
    severity: 'LOW',
    description: 'Ensure that Amazon Backup is integrated with Amazon Relational Database Service in order to manage RDS database instance snapshots',
    more_info: 'Amazon RDS creates and saves automated backups of your DB instance during the backup window of your DB instance. With Amazon Backup, you can centrally configure backup policies and rules, and monitor backup activity for AWS RDS database instances.',
    recommended_action: 'Enable RDS database instance snapshots to improve the reliability of your backup strategy.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
    apis: ['RDS:describeDBSnapshots'],

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

            let snapshots = describeDBSnapshots.data.find(snapshot => snapshot.SnapshotType && snapshot.SnapshotType.toLowerCase() === 'awsbackup');

            if (snapshots) {
                helpers.addResult(results, 0, 'Backup service is in use for RDS snapshots', region);
            } else {
                helpers.addResult(results, 2, 'Backup service is not in use for RDS snapshots', region);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
