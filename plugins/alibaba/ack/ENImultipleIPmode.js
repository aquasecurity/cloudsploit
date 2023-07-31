var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: ' ENI Multiple IP Mode Enabled ',
    category: 'ACK',
    domain: 'Containers',
    description: 'Ensure that Kubernetes Engine Clusters are configured with ENI multiple IP mode enabled using the Terway network plugin.',
    more_info: 'Alibaba Cloud ENI (Elastic Network Interface) supports assigning ranges of internal IP addresses as aliases to a single virtual machine\'s ENI network interfaces. This is useful if you have lots of services running on a VM and you want to assign each service a different IP address without quota limitation.',
    link: 'https://www.alibabacloud.com/help/doc-detail/97467.htm?spm=a2c63.p38356.b99.209.1e7b2c60a1yuxS',
    recommended_action: 'Recreate Kubernetes clusters and select Terway for Network Plugin option during cluster creation.',
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
                let clusterMeta = JSON.parse(cluster.meta_data);

                if (clusterMeta.Capabilities && clusterMeta.Capabilities.Network === 'terway-eniip') {
                    helpers.addResult(results, 0,
                        'Cluster has ENI Multiple IP Mode enabled',
                        defaultRegion, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Cluster does not have ENI Multiple IP Mode enabled',
                        defaultRegion, resource);
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
