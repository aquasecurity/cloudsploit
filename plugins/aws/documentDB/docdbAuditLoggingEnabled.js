var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'DocumentDB Audit Logging Enabled',
    category: 'DocumentDB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that audit logging is enabled for DocumentDB clusters.',
    more_info: 'Audit logging in Amazon DocumentDB provides visibility into authentication events, queries, and data changes. It helps detect unauthorized access, supports troubleshooting, and meets compliance requirements. Logs should be sent to CloudWatch or a SIEM for centralized monitoring and alerting.',
    recommended_action: 'Modify DocumentDB cluster and enable audit logging feature.',
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
                    cluster.EnabledCloudwatchLogsExports.includes('audit')) {
                    helpers.addResult(results, 0, 'DocumentDB cluster has audit logging enabled', region, cluster.DBClusterArn);
                } else {
                    helpers.addResult(results, 2, 'DocumentDB cluster does not have audit logging enabled', region, cluster.DBClusterArn);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
