var expect = require('chai').expect;
var aksHasTags = require('./aksClusterHasTags');
const listCluster = [
    {
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': { 'key': 'value' },
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "provisioningState": "Succeeded",
        "kubernetesVersion": "1.17.9",
        "dnsPrefix": "absbaks2-dns",
        "fqdn": "absbaks2-dns-9b85fd77.hcp.eastus.azmk8s.io",
        "agentPoolProfiles": [
            {
                "name": "agentpool",
                "count": 2,
                "vmSize": "Standard_DS2_v2",
                "osDiskSizeGB": 128,
                "maxPods": 110,
                "type": "VirtualMachineScaleSets",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.17.9",
                "nodeLabels": {},
                "mode": "System",
                "osType": "Linux"
            },
            {
                "name": "test",
                "count": 1,
                "vmSize": "Standard_DS1_v2",
                "osDiskSizeGB": 128,
                "maxPods": 110,
                "type": "VirtualMachineScaleSets",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.16.10",
                "mode": "User",
                "osType": "Linux"
            }
        ],
        "nodeResourceGroup": "MC_ABSBAKS2_absbaks2_eastus",
        "enableRBAC": true,
        "maxAgentPools": 10,
        "apiServerAccessProfile": {
            "enablePrivateCluster": false
        }
    },
        {
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
        "location": "eastus",
        'tags': {},
        "name": "absbaks2",
        "type": "Microsoft.ContainerService/ManagedClusters",
        "sku": {
            "name": "Basic",
            "tier": "Free"
        },
        "provisioningState": "Succeeded",
        "kubernetesVersion": "1.17.9",
        "dnsPrefix": "absbaks2-dns",
        "fqdn": "absbaks2-dns-9b85fd77.hcp.eastus.azmk8s.io",
        "agentPoolProfiles": [
            {
                "name": "agentpool",
                "count": 2,
                "vmSize": "Standard_DS2_v2",
                "osDiskSizeGB": 128,
                "maxPods": 110,
                "type": "VirtualMachineScaleSets",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.17.9",
                "nodeLabels": {},
                "mode": "System",
                "osType": "Linux"
            },
            {
                "name": "test",
                "count": 1,
                "vmSize": "Standard_DS1_v2",
                "osDiskSizeGB": 128,
                "maxPods": 110,
                "type": "VirtualMachineScaleSets",
                "provisioningState": "Succeeded",
                "orchestratorVersion": "1.17.9",
                "mode": "User",
                "osType": "Linux"
            }
        ],
        "nodeResourceGroup": "MC_ABSBAKS2_absbaks2_eastus",
        "enableRBAC": true,
        "maxAgentPools": 10,
        "apiServerAccessProfile": {
            "enablePrivateCluster": false
        }
    }
]

const createCache = (err, list) => {
    return {
        managedClusters: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('aksHasTags', function() {
    describe('run', function() {
        it('should give passing result if no managed clusters', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[]);
            aksHasTags.run(cache, {}, callback);
        });

        it('should give Unknown result if unable to query AKS', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Kubernetes clusters');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,null);
            aksHasTags.run(cache, {}, callback);
        })

        it('should give failing result if Kubernetes Service does not have tags', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AKS cluster does not have tags');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null,[listCluster[1]]);
            aksHasTags.run(cache, {}, callback);
        });

        it('should give passing result if Kubernetes Service have tags', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AKS cluster has tags');
                expect(results[0].region).to.equal('eastus');
                done();
            };
            const cache = createCache(null,[listCluster[0]]);
            aksHasTags.run(cache, {}, callback);
        });
    });
});