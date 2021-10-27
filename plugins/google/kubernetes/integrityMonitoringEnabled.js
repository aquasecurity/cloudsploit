var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Integrity Monitoring Enabled',
    category: 'Kubernetes',
    description: 'Ensures all Kubernetes shielded cluster node have integrity monitoring enabled',
    more_info: 'Integrity Monitoring feature automatically monitors the integrity of your cluster nodes.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/shielded-gke-nodes#integrity_monitoring',
    recommended_action: 'Enable Integrity Monitoring feature for your cluster nodes',
    apis: ['clusters:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        var project = projects.data[0].name;

        async.each(regions.clusters, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['clusters', 'list', region]);

            if (!clusters) return rcb();

            if (clusters.err || !clusters.data) {
                helpers.addResult(results, 3, 'Unable to query Kubernetes clusters', region, null, null, clusters.err);
                return rcb();
            }

            if (!clusters.data.length) {
                helpers.addResult(results, 0, 'No Kubernetes clusters found', region);
                return rcb();
            }

            clusters.data.forEach(cluster => {
                let location;
                if (cluster.locations) {
                    location = cluster.locations.length === 1 ? cluster.locations[0] : cluster.locations[0].substring(0, cluster.locations[0].length - 2);
                } else location = region;

                let disbaledIntegrityMonitoringNodes = [];
                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);
                if (cluster.nodePools &&
                    cluster.nodePools.length) {
                    cluster.nodePools.forEach(nodePool => {
                        if (!nodePool.config || !nodePool.config.shieldedInstanceConfig || !nodePool.config.shieldedInstanceConfig.enableIntegrityMonitoring) disbaledIntegrityMonitoringNodes.push(nodePool.name);
                    });
                    if (disbaledIntegrityMonitoringNodes.length) {
                        helpers.addResult(results, 2,
                            `Integrity Monitoring is disabled for these node pools: ${disbaledIntegrityMonitoringNodes.join(', ')}`, region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Integrity Monitoring is enabled for all node pools', region, resource);
                    }
                } else {
                    helpers.addResult(results, 0, 'No node pools found', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};