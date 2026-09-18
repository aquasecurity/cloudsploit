var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Audit Logging Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that Amazon Neptune database clusters have audit logging enabled.',
    more_info: 'Neptune audit logging records database access and management activities and delivers the logs to AWS CloudTrail. This helps in security monitoring, compliance auditing, and forensic analysis.',
    recommended_action: 'Modify the Neptune DB cluster and enable audit logging.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/security-logging.html',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster','neptune:ModifyDBCluster'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.neptune, function(region, rcb) {
            var describeDBClusters = helpers.addSource(cache,source,
                ['neptune', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results,3,
                    `Unable to list Neptune database clusters: ${helpers.addError(describeDBClusters)}`,region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results,0,
                    'No Neptune database clusters found',region);
                return rcb();
            }

            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn || cluster.Engine !== 'neptune') continue;
                if (cluster.EnableAuditLog) {
                    helpers.addResult(results,0,'Neptune audit logging is enabled',region,cluster.DBClusterArn);
                } else {
                    helpers.addResult(results,2,'Neptune audit logging is disabled',region,cluster.DBClusterArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
