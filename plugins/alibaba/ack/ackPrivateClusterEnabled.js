var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'ACK Private Cluster Enabled',
    category: 'ACK',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Kubernetes clusters are created with private cluster enabled.',
    more_info: 'Private cluster restricts access to the Kubernetes API server from the public internet, making it more secure. In a private cluster, the API Server Public Network Endpoint is not exposed to the internet. This reduces the risk of unauthorised access and helps protect sensitive data and workloads. It is recommended to have Private Cluster enabled for better security.',
    link: 'https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/control-public-access-to-the-api-server-of-a-cluster',
    recommended_action: 'Recreate Kubernetes clusters with public access disabled.',
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
 
            if (cluster.master_url) {
                try {
                    var masterUrl = JSON.parse(cluster.master_url);
                    
                    if (masterUrl.api_server_endpoint && masterUrl.api_server_endpoint !== '') {
                        helpers.addResult(results, 2, 'Cluster does not have private cluster feature enabled', defaultRegion, resource);
                    } else {
                        helpers.addResult(results, 0, 'Cluster has private cluster feature enabled', defaultRegion, resource);
                    }
                } catch (e) {
                    helpers.addResult(results, 3, `Master_url of cluster ${cluster.cluster_id} can not be parsed`, defaultRegion, resource);
                }
            } else {
                helpers.addResult(results, 3, `Could not find master_url info for cluster ${cluster.cluster_id}`, defaultRegion, resource);
            }
        });

        callback(null, results, source);
    }
};
