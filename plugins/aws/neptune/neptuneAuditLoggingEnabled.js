var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Audit Logging Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that audit logging is enabled for Neptune clusters to capture database activities, including login attempts, queries, and modifications.',
    more_info: 'Enable that audit logging to capture database activities, including login attempts, queries, and modifications. Send the logs to Amazon CloudWatch or a centralized log management system for analysis and monitoring.',
    recommended_action: 'Modify Neptune cluster and enable audit logging feature.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/enable-cloudwatch-logs.html',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster','neptune:ModifyDBCluster','neptune:DeleteDBCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.neptune, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['neptune', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list Neptune database clusters: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No Neptune database clusters found', region);
                return rcb();
            }
            
            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn || cluster.Engine !== 'neptune') continue;

                let resource = cluster.DBClusterArn;

                if (cluster.EnabledCloudwatchLogsExports &&
                    cluster.EnabledCloudwatchLogsExports.length &&
                    cluster.EnabledCloudwatchLogsExports.includes('audit')) {
                    helpers.addResult(results, 0, 'Neptune database cluster has audit logging enabled', region, resource);
                } else {
                    helpers.addResult(results, 2, 'Neptune database cluster does not have audit logging enabled', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};

