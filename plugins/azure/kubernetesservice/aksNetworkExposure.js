var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Internet Exposure',
    category: 'Kubernetes Service',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensures that Azure Kubernetes clusters are not exposed to the internet.',
    more_info: 'In a private cluster, the control plane or API server has internal IP addresses that are defined in the RFC1918 - Address Allocation for Private Internet document. By using a private cluster, you can ensure network traffic between your API server and your node pools remains on the private network only.',
    recommended_action: 'Modify cluster network configuration and enable private cluster feature.',
    link: 'https://learn.microsoft.com/en-us/azure/aks/private-clusters',
    apis: ['managedClusters:list', 'resourceGroups:list', 'resources:listByResourceGroup', 'networkSecurityGroups:listAll', 'virtualNetworks:listAll',],
    realtime_triggers: ['microsoftcontainerservice:managedclusters:write', 'microsoftcontainerservice:managedclusters:delete', 'microsoftnetwork:networksecuritygroups:write','microsoftnetwork:networksecuritygroups:delete', 'microsoftnetwork:virtualnetworks:write','microsoftnetwork:virtualnetworks:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.managedClusters, function(location, rcb) {
            var managedClusters = helpers.addSource(cache, source,
                ['managedClusters', 'list', location]);

            if (!managedClusters) return rcb();

            if (managedClusters.err || !managedClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Kubernetes clusters: ' + helpers.addError(managedClusters), location);
                return rcb();
            }

            if (!managedClusters.data.length) {
                helpers.addResult(results, 0, 'No existing Kubernetes clusters', location);
                return rcb();
            }
            var resources = helpers.addSource(cache, source,
                ['resources', 'listByResourceGroup', location]);

            let networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);

            var virtualNetworks = helpers.addSource(cache, source,
                ['virtualNetworks', 'listAll', location]);

            for (let cluster of managedClusters.data) {
                if (!cluster.id) continue;

                // check for api server access
                let publicIPs =  ['*', '0.0.0.0', '0.0.0.0/0', '<nw/0>', '/0', '::/0', 'internet'];
                let internetExposed = '';
                if (cluster.apiServerAccessProfile && !cluster.apiServerAccessProfile.enablePrivateCluster) {
                    let authorizedIPRanges = cluster.apiServerAccessProfile.authorizedIpRanges;
                    if (!authorizedIPRanges || !authorizedIPRanges.length || authorizedIPRanges.some(range => publicIPs.includes(range))) {
                        internetExposed = 'public endpoint access';
                    }
                }
                if (!internetExposed || !internetExposed.length) {
                    // check NSG rules for node pools
                    let securityGroupIDs = [], subnets = [], vnets = [], securityGroups = [];

                    if (networkSecurityGroups && !networkSecurityGroups.err && networkSecurityGroups.data && networkSecurityGroups.data.length) {
                        if (virtualNetworks && !virtualNetworks.err && virtualNetworks.data && virtualNetworks.data.length) {
                            if (cluster.agentPoolProfiles && cluster.agentPoolProfiles.length) {
                                subnets = cluster.agentPoolProfiles.map(profile => profile.vnetSubnetId);
                            }

                            if (cluster.nodeResourceGroup && resources && Object.keys(resources).length) {
                                let groupID = Object.keys(resources).find(key => key.toLowerCase().endsWith(cluster.nodeResourceGroup.toLowerCase()));
                                if (groupID && resources[groupID] && resources[groupID].data && resources[groupID].data.length) {
                                    vnets = resources[groupID].data.filter(resource => resource.type === 'Microsoft.Network/virtualNetworks').map(vnet => vnet.id);

                                }
                            }

                            virtualNetworks.data.forEach(vnet => {
                                if (vnet.subnets && vnet.subnets.length) {
                                    vnet.subnets.forEach(subnet => {
                                        if ((subnets.includes(subnet.id) || vnets.includes(vnet.id)) && subnet.properties && subnet.properties.networkSecurityGroup && subnet.properties.networkSecurityGroup.id) {
                                            securityGroupIDs.push(subnet.properties.networkSecurityGroup.id);
                                        }
                                    });
                                }
                            });
                            securityGroups = networkSecurityGroups.data.filter(nsg => securityGroupIDs.includes(nsg.id));
                            internetExposed = helpers.checkNetworkExposure(cache, source, [], securityGroups, location, results, {}, cluster);
                        }
                    }
                }

                if (internetExposed && internetExposed.length) {
                    helpers.addResult(results, 2, `AKS cluster is exposed to the internet through ${internetExposed}`, location, cluster.id);
                } else {
                    helpers.addResult(results, 0, 'AKS cluster is not exposed to the internet', location, cluster.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
