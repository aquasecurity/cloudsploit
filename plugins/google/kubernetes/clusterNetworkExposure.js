var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Network Exposure',
    category: 'Kubernetes',
    domain: 'Containers',
    severity: 'Info',
    description: 'Check if GKE clusters are exposed to the internet.',
    more_info: 'GKE clusters exposed to the internet are at a higher risk of unauthorized access, data breaches, and cyberattacks. It’s crucial to limit exposure by securing the Kubernetes API, nodes, and services through proper configuration of network, firewall rules, and private clusters.',
    link: 'https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters',
    recommended_action: 'Secure GKE clusters by enabling private clusters, restricting access to the Kubernetes API, and ensuring nodes and services are protected through properly configured firewall rules and network policies.',
    apis: ['kubernetes:list', 'firewalls:list'],
    realtime_triggers: ['container.ClusterManager.CreateCluster', 'container.ClusterManager.DeleteCluster','container.ClusterManager.UpdateCluster', 'container.ClusterManager.CreateNodePool','container.ClusterManager.DeleteNodePool',
        'compute.firewalls.insert', 'compute.firewalls.delete', 'compute.firewalls.patch'],

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

        let firewalls = helpers.addSource(
            cache, source, ['firewalls', 'list', 'global']);

        if (!firewalls || firewalls.err || !firewalls.data) {
            helpers.addResult(results, 3, 'Unable to query firewall rules', 'global', null, null, firewalls.err);
        }

        if (!firewalls.data.length) {
            helpers.addResult(results, 0, 'No firewall rules found', 'global');
        }

        async.each(regions.kubernetes, function(region, rcb){
            let clusters = helpers.addSource(cache, source,
                ['kubernetes', 'list', region]);

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

                let resource = helpers.createResourceName('clusters', cluster.name, project, 'location', location);
                let internetExposed = '';
                if (helpers.checkClusterExposure(cluster)) {
                    internetExposed = 'public endpoint access';
                } else {
                    let clusterNetwork = cluster.networkConfig && cluster.networkConfig.network ? cluster.networkConfig.network : cluster.network;
                    if (clusterNetwork && !clusterNetwork.includes('/')) clusterNetwork = `${clusterNetwork}`;
                    let firewallRules = firewalls.data.filter(rule => {
                        return rule.network && rule.network.endsWith(clusterNetwork);
                    });


                    let isExposed = helpers.checkFirewallRules(firewallRules);
                    if (isExposed && isExposed.exposed && isExposed.networkName) {
                        internetExposed = isExposed.networkName;
                    } else {
                        // check node pools
                        let exposedNodePools = Array.isArray(cluster.nodePools) ? cluster.nodePools.filter(nodepool => nodepool.networkConfig && !nodepool.networkConfig.enablePrivateNodes).map(nodepool => nodepool.name) : [] ;
                        if (exposedNodePools.length) {
                            internetExposed = `node pools ${exposedNodePools.join(',')}`;
                        }
                    }

                }
                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2, `Cluster is exposed to the internet through ${internetExposed}`, region, resource);
                } else {
                    helpers.addResult(results, 0, 'Cluster is not exposed to the internet', region, resource);
                }


            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

