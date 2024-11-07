var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Kubernetes Web Dashboard Disabled',
    category: 'ACK',
    domain: 'Containers',
    severity: 'Medium',
    description: 'Ensure that Kubernetes cluster web UI/Dashboard is not enabled.',
    more_info: 'The Kubernetes Web UI (Dashboard) is backed by a highly privileged Kubernetes Service Account. It is recommended to use ACK User Console instead of Dashboard to avoid any privileged escalation via compromise the dashboard.',
    link: 'https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/',
    recommended_action: 'In ACK console, select the target cluster,choose the kube-system namespace in the Namespace pop-menu, input "dashboard" in the deploy filter bar, verify no result exists after the filter, and delete the dashboard deployment by selecting Delete in the More pop-menu.',
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
                    var masterUrlData = JSON.parse(cluster.master_url);
                    var dashboardEndpoint = masterUrlData.dashboard_endpoint;
                
                    if (dashboardEndpoint && dashboardEndpoint.trim() !== '') {
                        helpers.addResult(results, 2, 'Kubernetes cluster has dashboard enabled', defaultRegion, resource);
                    } else {
                        helpers.addResult(results, 0, 'Kubernetes cluster has dashboard disabled', defaultRegion, resource);
                    }
                } catch (e) {
                    helpers.addResult(results, 3, `Master_url of cluster ${cluster.cluster_id} can not be parsed`, defaultRegion, resource);
                }
            } else {
                helpers.addResult(results, 3,
                    `Could not find meta-data info of master_url for cluster ${cluster.cluster_id}`,
                    defaultRegion, resource);
            }
        });

        callback(null, results, source);
    }
};
