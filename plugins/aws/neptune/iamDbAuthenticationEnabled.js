var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune IAM Database Authentication Enabled',
    category: 'Neptune',
    description: 'Ensures IAM Database Authentication is enabled for Neptune database clusters to manage database access',
    more_info: 'AWS Identity and Access Management (IAM) can used to authenticate to your Neptune DB instance or DB cluster.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html',
    recommended_action: 'Modify the Neptune cluster to enable deletion protection.',
    apis: ['Neptune:describeDBClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.neptune, function(region, rcb) {
            var describeDBClusters = helpers.addSource(cache, source,
                ['neptune', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Neptune clusters: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0, 'No Neptune clusters found', region);
                return rcb();
            }

            describeDBClusters.data.forEach(cluster => {
                if (!cluster.DBClusterArn) return;

                if (cluster.IAMDatabaseAuthenticationEnabled) {
                    helpers.addResult(results, 0,
                        'DB cluster has IAM Database Authentication enabled', region, cluster.DBClusterArn);
                } else {
                    helpers.addResult(results, 2,
                        'DB cluster does not have IAM Database Authentication enabled', region, cluster.DBClusterArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
