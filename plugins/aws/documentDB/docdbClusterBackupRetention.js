var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Backup Retention',
    category: 'DocumentDB',
    domain: 'Databases',
    description: 'Ensure that your Amazon DocumentDB clusters have set a minimum backup retention period.',
    more_info: 'DocumentDB cluster provides feature to retain incremental backups between 1 and 35 allowing you to quickly restore to any point within the backup retention period. Ensure that you have sufficient backup retention period configured in order to restore your data in the event of failure.',
    recommended_action: 'Modify DocumentDb cluster to configure sufficient backup retention period.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-modify.html',
    apis: ['DocDB:describeDBClusters'],
    settings: {
        doc_db_backup_retention_threshold: {
            name: 'DocDB Cluster Minimum Backup Retention Period',
            description: 'Desired number of days for DocumentDB cluster backup retention period.',
            regex: '^[1-35]*$',
            default: 7
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var doc_db_backup_retention_threshold = parseInt(settings.doc_db_backup_retention_threshold || this.settings.doc_db_backup_retention_threshold.default); 

        async.each(regions.docdb, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['docdb', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list DocumentDB clusters: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No DocumentDB clusters found', region);
                return rcb();
            }
            
            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn) continue;

                let resource = cluster.DBClusterArn;

                if (cluster.BackupRetentionPeriod && cluster.BackupRetentionPeriod >=  doc_db_backup_retention_threshold) {
                    helpers.addResult(results, 0,
                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} of ${doc_db_backup_retention_threshold} days limit`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} of ${doc_db_backup_retention_threshold} days limit`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
