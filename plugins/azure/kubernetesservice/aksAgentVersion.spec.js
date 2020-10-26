var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./aksAgentVersion');

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

describe('aksAgentVersion', function() {
    describe('run', function() {
        it('should give passing result if no managed clusters', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Kubernetes clusters found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if the Kubernetes clusters does not have the latest version for one pool', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('does not have the cluster Kubernetes version');
                expect(results[1].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
                        "location": "eastus",
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
                    }
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if the Kubernetes clusters have the latest version for all the agent pool', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(2);
                results.forEach(result =>{
                    expect(result.status).to.equal(0);
                    expect(result.message).to.include('has the cluster Kubernetes version');
                    expect(result.region).to.equal('eastus');});
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourcegroups/ABSBAKS2/providers/Microsoft.ContainerService/managedClusters/absbaks2",
                        "location": "eastus",
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
            );

            auth.run(cache, {}, callback);
        })
    })
})