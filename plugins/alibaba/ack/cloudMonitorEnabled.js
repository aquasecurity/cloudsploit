var helpers = require('../../../helpers/alibaba');

module.exports = {
    title: 'Cloud Monitor Enabled',
    category: 'ACK',
    domain: 'Containers',
    description: 'Ensure Cloud Monitor is set to Enabled on Kubernetes Engine Clusters.',
    more_info: '',
    link: '',
    recommended_action: 'Recreate Kubernetes clusters and set CloudMonitor Agent to enabled under creation options ',
    apis: ['ACK:describeClustersV1', 'STS:GetCallerIdentity', 'ACK:describeClusterDetail'],

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

             var describeClusterDetail = helpers.addSource(cache, source, ['ack', 'describeClusterDetail', defaultRegion, cluster.cluster_id]);

            if (!describeClusterDetail)  return;

            if (describeClusterDetail.err || !describeClusterDetail.data ||!describeClusterDetail.data.length) {
                helpers.addResult(results, 3, `Unable to query ACK clusters: ${helpers.addError(describeClusterDetail)}`, defaultRegion);
                return;
            }

              console.log(describeClusterDetail);







            
        });

        callback(null, results, source);
    }
};
