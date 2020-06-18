var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./aksLatestVersion');

const createCache = (err, list, get) => {
    return {
        managedClusters: {
            list: {
                'eastus': {
                    err: err,
                    data: list
                }
            },
            getUpgradeProfile: {
                'eastus': get
            }
        }
    }
};

describe('aksLatestVersion', function() {
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

        it('should give failing result if the Kubernetes clusters does not have the latest version installed', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The managed cluster does not have the latest Kubernetes version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters",
                        "location": "eastus",
                        "name": "clustername1"
                    }
                ],
                {
                    "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters": {
                        data: {
                            "id": "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters/kubtest3/upgradeprofiles/default",
                            "name": "default",
                            "type": "Microsoft.ContainerService/managedClusters/upgradeprofiles",
                            "controlPlaneProfile": {
                                "kubernetesVersion": "1.11.10",
                                "osType": "Linux",
                                "upgrades": [
                                    "1.12.7",
                                    "1.12.8"
                                ]
                            },
                            "agentPoolProfiles": [
                                {
                                    "kubernetesVersion": "1.11.10",
                                    "osType": "Linux",
                                    "upgrades": [
                                        "1.12.7",
                                        "1.12.8"
                                    ]
                                }
                            ],
                            "error": false,
                            "location": "centralus",
                            "storageAccount": {
                                "name": "kubtest3"
                            }
                        }
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if the Kubernetes clusters have the latest version installed', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The managed cluster has the latest Kubernetes version');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters",
                        "location": "eastus",
                        "name": "clustername1"
                    }
                ],
                {
                    "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters": {
                        data: {
                            "id": "/subscriptions/subid1/providers/Microsoft.ContainerService/managedClusters/kubtest3/upgradeprofiles/default",
                            "name": "default",
                            "type": "Microsoft.ContainerService/managedClusters/upgradeprofiles",
                            "controlPlaneProfile": {
                                "kubernetesVersion": "1.11.10",
                                "osType": "Linux",
                                "upgrades": []
                            },
                            "agentPoolProfiles": [
                                {
                                    "kubernetesVersion": "1.11.10",
                                    "osType": "Linux",
                                    "upgrades": []
                                }
                            ],
                            "error": false,
                            "location": "centralus",
                            "storageAccount": {
                                "name": "kubtest3"
                            }
                        }
                    }
                }
            );

            auth.run(cache, {}, callback);
        })
    })
})