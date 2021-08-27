var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Network Policy Enabled',
    category: 'ACK',
    description: 'Ensure that Kubernetes Engine Clusters are configured to enable NetworkPolicy.',
    more_info: 'By default, kubernetes pods accept traffic from any source. But with NetworkPolicy, pods can be configured ' +
        'to reject any connections which are not allowed by any NetworkPolicy.',
    link: 'https://www.alibabacloud.com/help/doc-detail/97467.htm?spm=a2c63.p38356.b99.209.1e7b2c60a1yuxS',
    recommended_action: 'Recreate Kubernetes clusters and select Terway for Network Plug-in option',
    apis: ['ACK:describeClustersV1', 'STS:GetCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        var describeClusters = helpers.addSource(cache, source, ['ack', 'describeClustersV1', defaultRegion]);

        if (!describeClusters) return callback(null, results, source);

        if (describeClusters.err || !describeClusters.data) {
            helpers.addResult(results, 3, `Unable to query ACK clusters: ${helpers.addError(describeClusters)}`, defaultRegion);
            return callback(null, results, source);
        }

        if (!describeClusters.data.length) {
            helpers.addResult(results, 0, 'No ACK clusters found', defaultRegion);
            return callback(null, results, source);
        }

        describeClusters.data.forEach(cluster => {
            if (!cluster.cluster_id) return;

            var resource = helpers.createArn('cs', accountId, 'cluster', cluster.cluster_id, defaultRegion);

            if (cluster.meta_data) {
                let found = false;
                let clusterMeta = JSON.parse(cluster.meta_data);
                if (clusterMeta.Addons && clusterMeta.Addons.length) found = clusterMeta.Addons.find(addon => addon.name == 'terway-eniip' && !addon.disabled);

                if (found) {
                    helpers.addResult(results, 0,
                        'Cluster has NetworkPolicy enabled', defaultRegion, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Cluster does not have NetworkPolicy enabled', defaultRegion, resource);
                }
            } else {
                helpers.addResult(results, 3,
                    `Could not find meta-data info for cluster ${cluster.cluster_id}`,
                    defaultRegion, resource);
            }
        });

        callback(null, results, source);
    }
};
