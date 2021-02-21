var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Deletion Protection Enabled',
    category: 'Neptune',
    description: 'Ensures deletion protection is enabled for Neptune database clusters',
    more_info: 'When a database cluster is configured with deletion protection, the cluster cannot be deleted by any user.',
    link: 'https://aws.amazon.com/about-aws/whats-new/2020/01/amazon-neptune-provides-data-base-deletion-protection/',
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
                    'Unable to query for Neptune clusters: ' + helpers.addError(describeDBClusters), region);
                return rcb();
            }
            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0, 'No Neptune clusters found', region);
                return rcb();
            }

            describeDBClusters.data.forEach(cluster => {
                if (!cluster.DBClusterArn) return;
                if (cluster.DeletionProtection) {
                    helpers.addResult(results, 0,
                        'DB cluster has deletion protection enabled', region, cluster.DBClusterArn);
                } else {
                    helpers.addResult(results, 2,
                        'DB cluster does not have deletion protection enabled', region, cluster.DBClusterArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
