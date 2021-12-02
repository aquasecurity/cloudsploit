var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Backup Retention',
    category: 'DocumentDB',
    domain: 'Databases',
    description: 'Ensure that your Amazon DocumentDB clusters have set a minimum backup retention period.',
    more_info: `DocumentDB cluster provides feature to retain incremental backups between 1 and 35 allowing
                you to quickly restore to any point within the backup retention period. Ensure that you have
                sufficient backup retention period configured in order to restore your data in the event of failure.`,
    recommended_action: 'Modify DocumentDb cluster to configure sufficient backup retention period.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-modify.html',
    apis: ['DocDB:describeDBClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var RECOMMENDED_THRESHOLD = 7;
    
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

                if (cluster.BackupRetentionPeriod && cluster.BackupRetentionPeriod > RECOMMENDED_THRESHOLD) {
                    helpers.addResult(results, 0,
                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} days \
                        which is greater than or equal to the recommended period of ${RECOMMENDED_THRESHOLD} days`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `DocumentDB cluster has a backup retention period of ${cluster.BackupRetentionPeriod} days \
                        which is less than the recommended period of ${RECOMMENDED_THRESHOLD} days`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
