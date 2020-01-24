var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./loggingEnabled');

const createCache = (err, data) => {
    return {
        clusters: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('loggingEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a clusters error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Kubernetes clusters');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no clusters are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Kubernetes clusters found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if logging is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Logging is enabled on the cluster');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-2",
                        "nodeConfig": {
                            "machineType": "n1-standard-1",
                            "diskSizeGb": 100,
                            "oauthScopes": [
                                "https://www.googleapis.com/auth/devstorage.read_only",
                                "https://www.googleapis.com/auth/logging.write",
                                "https://www.googleapis.com/auth/monitoring",
                                "https://www.googleapis.com/auth/servicecontrol",
                                "https://www.googleapis.com/auth/service.management.readonly",
                                "https://www.googleapis.com/auth/trace.append"
                            ],
                            "metadata": {
                                "disable-legacy-endpoints": "true"
                            },
                            "imageType": "COS",
                            "serviceAccount": "default",
                            "diskType": "pd-standard"
                        },
                        "masterAuth": {
                            "clusterCaCertificate": "clusterCaCertificateText"
                        },
                        "loggingService": "logging.googleapis.com",
                        "monitoringService": "monitoring.googleapis.com",
                        "network": "default",
                        "clusterIpv4Cidr": "10.4.0.0/14",
                        "addonsConfig": {
                            "httpLoadBalancing": {},
                            "horizontalPodAutoscaling": {},
                            "kubernetesDashboard": {
                                "disabled": true
                            },
                            "networkPolicyConfig": {
                                "disabled": true
                            },
                            "istioConfig": {
                                "disabled": true
                            }
                        },
                        "subnetwork": "default",
                        "nodePools": [
                            {
                                "name": "default-pool",
                                "config": {
                                    "machineType": "n1-standard-1",
                                    "diskSizeGb": 100,
                                    "oauthScopes": [
                                        "https://www.googleapis.com/auth/devstorage.read_only",
                                        "https://www.googleapis.com/auth/logging.write",
                                        "https://www.googleapis.com/auth/monitoring",
                                        "https://www.googleapis.com/auth/servicecontrol",
                                        "https://www.googleapis.com/auth/service.management.readonly",
                                        "https://www.googleapis.com/auth/trace.append"
                                    ],
                                    "metadata": {
                                        "disable-legacy-endpoints": "true"
                                    },
                                    "imageType": "COS",
                                    "serviceAccount": "default",
                                    "diskType": "pd-standard"
                                },
                                "initialNodeCount": 3,
                                "autoscaling": {},
                                "management": {
                                    "autoUpgrade": true,
                                    "autoRepair": true
                                },
                                "maxPodsConstraint": {
                                    "maxPodsPerNode": "110"
                                },
                                "podIpv4CidrSize": 24,
                                "locations": [
                                    "us-central1-a"
                                ],
                                "selfLink": "https://container.googleapis.com/v1beta1/projects/frost-forest-281330/zones/us-central1-a/clusters/standard-cluster-2/nodePools/default-pool",
                                "version": "1.12.8-gke.10",
                                "instanceGroupUrls": [
                                    "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-central1-a/instanceGroupManagers/gke-standard-cluster-2-default-pool-941e601d-grp"
                                ],
                                "status": "RUNNING"
                            }
                        ],
                        "locations": [
                            "us-central1-a"
                        ],
                        "labelFingerprint": "a9dc16a7",
                        "legacyAbac": {},
                        "networkPolicy": {},
                        "ipAllocationPolicy": {
                            "useIpAliases": true,
                            "clusterIpv4Cidr": "10.4.0.0/14",
                            "servicesIpv4Cidr": "10.70.0.0/20",
                            "clusterSecondaryRangeName": "gke-standard-cluster-2-pods-c6001cf3",
                            "servicesSecondaryRangeName": "gke-standard-cluster-2-services-c6001cf3",
                            "clusterIpv4CidrBlock": "10.4.0.0/14",
                            "servicesIpv4CidrBlock": "10.70.0.0/20"
                        },
                        "masterAuthorizedNetworksConfig": {
                            "enabled": true
                        },
                        "maintenancePolicy": {},
                        "networkConfig": {
                            "network": "projects/frost-forest-281330/global/networks/default",
                            "subnetwork": "projects/frost-forest-281330/regions/us-central1/subnetworks/default"
                        },
                        "privateCluster": true,
                        "masterIpv4CidrBlock": "10.127.0.0/28",
                        "defaultMaxPodsConstraint": {
                            "maxPodsPerNode": "110"
                        },
                        "authenticatorGroupsConfig": {},
                        "privateClusterConfig": {
                            "enablePrivateNodes": true,
                            "enablePrivateEndpoint": true,
                            "masterIpv4CidrBlock": "10.127.0.0/28",
                            "privateEndpoint": "10.127.0.2",
                            "publicEndpoint": "34.66.163.57"
                        },
                        "databaseEncryption": {
                            "state": "DECRYPTED"
                        },
                        "shieldedNodes": {},
                        "tierSettings": {
                            "tier": "STANDARD"
                        },
                        "selfLink": "https://container.googleapis.com/v1beta1/projects/frost-forest-281330/zones/us-central1-a/clusters/standard-cluster-2",
                        "zone": "us-central1-a",
                        "endpoint": "10.127.0.2",
                        "initialClusterVersion": "1.12.8-gke.10",
                        "currentMasterVersion": "1.12.8-gke.10",
                        "currentNodeVersion": "1.12.8-gke.10",
                        "createTime": "2019-08-20T20:21:44+00:00",
                        "status": "RUNNING",
                        "servicesIpv4Cidr": "10.70.0.0/20",
                        "instanceGroupUrls": [
                            "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-central1-a/instanceGroupManagers/gke-standard-cluster-2-default-pool-941e601d-grp"
                        ],
                        "currentNodeCount": 3,
                        "location": "us-central1-a"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if logging is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Logging is disabled on the Kubernetes cluster');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-1",
                        "nodeConfig": {
                            "machineType": "n1-standard-1",
                            "diskSizeGb": 100,
                            "oauthScopes": [
                                "https://www.googleapis.com/auth/devstorage.read_only",
                                "https://www.googleapis.com/auth/logging.write",
                                "https://www.googleapis.com/auth/monitoring",
                                "https://www.googleapis.com/auth/servicecontrol",
                                "https://www.googleapis.com/auth/service.management.readonly",
                                "https://www.googleapis.com/auth/trace.append"
                            ],
                            "metadata": {
                                "disable-legacy-endpoints": "true"
                            },
                            "imageType": "COS",
                            "serviceAccount": "default",
                            "diskType": "pd-standard"
                        },
                        "masterAuth": {
                            "clusterCaCertificate": "clusterCaCertificateText"
                        },
                        "loggingService": "none",
                        "monitoringService": "none",
                        "network": "default",
                        "clusterIpv4Cidr": "10.48.0.0/14",
                        "addonsConfig": {
                            "httpLoadBalancing": {},
                            "horizontalPodAutoscaling": {},
                            "kubernetesDashboard": {
                                "disabled": true
                            },
                            "networkPolicyConfig": {
                                "disabled": true
                            },
                            "istioConfig": {
                                "disabled": true
                            }
                        },
                        "subnetwork": "default",
                        "nodePools": [
                            {
                                "name": "default-pool",
                                "config": {
                                    "machineType": "n1-standard-1",
                                    "diskSizeGb": 100,
                                    "oauthScopes": [
                                        "https://www.googleapis.com/auth/devstorage.read_only",
                                        "https://www.googleapis.com/auth/logging.write",
                                        "https://www.googleapis.com/auth/monitoring",
                                        "https://www.googleapis.com/auth/servicecontrol",
                                        "https://www.googleapis.com/auth/service.management.readonly",
                                        "https://www.googleapis.com/auth/trace.append"
                                    ],
                                    "metadata": {
                                        "disable-legacy-endpoints": "true"
                                    },
                                    "imageType": "COS",
                                    "serviceAccount": "default",
                                    "diskType": "pd-standard"
                                },
                                "initialNodeCount": 3,
                                "autoscaling": {
                                    "enabled": true,
                                    "minNodeCount": 1,
                                    "maxNodeCount": 3
                                },
                                "management": {
                                    "autoUpgrade": true,
                                    "autoRepair": true
                                },
                                "maxPodsConstraint": {
                                    "maxPodsPerNode": "110"
                                },
                                "podIpv4CidrSize": 24,
                                "locations": [
                                    "us-east1-b",
                                    "us-east1-c",
                                    "us-east1-d"
                                ],
                                "selfLink": "https://container.googleapis.com/v1beta1/projects/frost-forest-281330/locations/us-east1/clusters/standard-cluster-1/nodePools/default-pool",
                                "version": "1.12.8-gke.10",
                                "instanceGroupUrls": [
                                    "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-b/instanceGroupManagers/gke-standard-cluster-1-default-pool-60ff7186-grp",
                                    "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-c/instanceGroupManagers/gke-standard-cluster-1-default-pool-f7958043-grp",
                                    "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-d/instanceGroupManagers/gke-standard-cluster-1-default-pool-51806d28-grp"
                                ],
                                "status": "RUNNING"
                            }
                        ],
                        "locations": [
                            "us-east1-b",
                            "us-east1-c",
                            "us-east1-d"
                        ],
                        "labelFingerprint": "a9dc16a7",
                        "legacyAbac": {},
                        "networkPolicy": {},
                        "ipAllocationPolicy": {
                            "useIpAliases": true,
                            "clusterIpv4Cidr": "10.48.0.0/14",
                            "servicesIpv4Cidr": "10.114.0.0/20",
                            "clusterSecondaryRangeName": "gke-standard-cluster-1-pods-1de110e2",
                            "servicesSecondaryRangeName": "gke-standard-cluster-1-services-1de110e2",
                            "clusterIpv4CidrBlock": "10.48.0.0/14",
                            "servicesIpv4CidrBlock": "10.114.0.0/20"
                        },
                        "masterAuthorizedNetworksConfig": {},
                        "maintenancePolicy": {},
                        "networkConfig": {
                            "network": "projects/frost-forest-281330/global/networks/default",
                            "subnetwork": "projects/frost-forest-281330/regions/us-east1/subnetworks/default"
                        },
                        "defaultMaxPodsConstraint": {
                            "maxPodsPerNode": "110"
                        },
                        "authenticatorGroupsConfig": {},
                        "databaseEncryption": {
                            "state": "DECRYPTED"
                        },
                        "shieldedNodes": {},
                        "tierSettings": {
                            "tier": "STANDARD"
                        },
                        "selfLink": "https://container.googleapis.com/v1beta1/projects/frost-forest-281330/locations/us-east1/clusters/standard-cluster-1",
                        "zone": "us-east1",
                        "endpoint": "35.231.28.40",
                        "initialClusterVersion": "1.12.8-gke.10",
                        "currentMasterVersion": "1.12.8-gke.10",
                        "currentNodeVersion": "1.12.8-gke.10",
                        "createTime": "2019-08-20T20:08:47+00:00",
                        "status": "RUNNING",
                        "servicesIpv4Cidr": "10.114.0.0/20",
                        "instanceGroupUrls": [
                            "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-b/instanceGroupManagers/gke-standard-cluster-1-default-pool-60ff7186-grp",
                            "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-c/instanceGroupManagers/gke-standard-cluster-1-default-pool-f7958043-grp",
                            "https://www.googleapis.com/compute/v1/projects/frost-forest-281330/zones/us-east1-d/instanceGroupManagers/gke-standard-cluster-1-default-pool-51806d28-grp"
                        ],
                        "currentNodeCount": 5,
                        "location": "us-east1"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});