var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'ACK Log Service Enabled',
    category: 'ACK',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Kubernetes Engine Clusters are configured to enable Log service.',
    more_info: 'Log Service allows you to collect, consume, and analyse logs from your containerised applications. By enabling Log Service on Kubernetes Engine Clusters, you can easily access and monitor log data from your containers, aiding in troubleshooting, analysis, and system monitoring.',
    link: 'https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/collect-log-data-from-containers-by-using-log-service',
    recommended_action: 'Recreate Kubernetes clusters and set enable log service feature.',
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
                try {
                    let clusterMeta = JSON.parse(cluster.meta_data);
       
                    if (clusterMeta.AuditProjectName) {
                        helpers.addResult(results, 0, 'Cluster has log service enabled', defaultRegion, resource);
                    } else {
                        helpers.addResult(results, 2, 'Cluster does not have log service enabled', defaultRegion, resource);
                    }
                } catch (e) {
                    helpers.addResult(results, 3, `Meta-data info of cluster ${cluster.cluster_id} can not be parsed`, defaultRegion, resource);
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
