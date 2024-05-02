var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Deletion Protection',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that your Amazon DocumentDB clusters have deletion protection feature enabled.',
    more_info: 'Enabling deletion protection feature for your Amazon DocumentDB clusters acts as a safety net, preventing accidental deletions and ensuring your data stays secure and accessible at all times.',
    recommended_action: 'Modify DocumentDb cluster and enable deletion protection.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/db-cluster-delete.html',
    apis: ['DocDB:describeDBClusters'],
    realtime_triggers: ['docdb:CreateDBCluster','docdb:ModifyDBCluster','docdb:DeleteDBCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

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

                if (cluster.DeletionProtection) {
                    helpers.addResult(results, 0,
                        'DocumentDB cluster has deletion protection enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'DocumentDB cluster does not have deletion protection enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
