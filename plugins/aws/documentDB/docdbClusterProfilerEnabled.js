var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Cluster Profiler Enabled',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that Amazon DocumentDB clusters have profiler feature enabled.',
    more_info: 'Enabling the Profiler for your Amazon DocumentDB clusters helps to monitor and log database operations. This makes it easier to identify slowest operations on cluster and fix performance issues by analyzing detailed logs in Amazon CloudWatch.',
    recommended_action: 'Modify DocumentDB cluster and enable profiler feature.',
    link: 'https://docs.aws.amazon.com/documentdb/latest/developerguide/profiling.html',
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

                if (cluster.EnabledCloudwatchLogsExports &&
                    cluster.EnabledCloudwatchLogsExports.length &&
                    cluster.EnabledCloudwatchLogsExports.includes('profiler')) {
                    helpers.addResult(results, 0, 'DocumentDB cluster has profiler feature enabled', region, cluster.DBClusterArn);
                } else {
                    helpers.addResult(results, 2, 'DocumentDB cluster does not have profiler feature enabled', region, cluster.DBClusterArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
