var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Instance Backup Retention',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that your Neptune Database Instances have set a minimum backup retention period.',
    more_info: 'Neptune Database Instance provides feature to retain incremental backups between 1 and 35 allowing you to quickly restore to any point within the backup retention period. Ensure that you have sufficient backup retention period configured in order to restore your data in the event of failure.',
    recommended_action: 'Modify Neptune Database Instance to configure sufficient backup retention period.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/backup-restore-overview.html',
    apis: ['Neptune:describeDBClusters'],
    settings: {
        neptune_db_backup_retention_threshold: {
            name: 'Neptune Instance Minimum Backup Retention Period',
            description: 'Desired number of days for Neptune Database Instance backup retention period.',
            regex: '^[1-35]*$',
            default: 7
        }
    },
    realtime_triggers: ['neptune:CreateDBCluster','neptune:ModifyDBCluster','neptune:DeleteDBCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var neptune_db_backup_retention_threshold = parseInt(settings.neptune_db_backup_retention_threshold || this.settings.neptune_db_backup_retention_threshold.default); 

        async.each(regions.neptune, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['neptune', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list Neptune database instances: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No Neptune database instances found', region);
                return rcb();
            }
            
            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn) continue;

                let resource = cluster.DBClusterArn;

                if (cluster.BackupRetentionPeriod && cluster.BackupRetentionPeriod >=  neptune_db_backup_retention_threshold) {
                    helpers.addResult(results, 0,
                        `Neptune database instance has a backup retention period of ${cluster.BackupRetentionPeriod} of ${neptune_db_backup_retention_threshold} days limit`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Neptune database instance has a backup retention period of ${cluster.BackupRetentionPeriod} of ${neptune_db_backup_retention_threshold} days limit`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
