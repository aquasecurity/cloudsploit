var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./privateClusterEnabled');

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

describe('privateClusterEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a clusters error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for clusters');
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
                expect(results[0].message).to.include('No clusters found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if private cluster is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Private cluster is enabled on the Kubernetes cluster');
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
                            "clusterCaCertificate": "clusterCaCertificate"
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
                        "podSecurityPolicyConfig": {
                            "enabled": true
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

        it('should give failing result if private cluster is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Private cluster is disabled on the Kubernetes cluster');
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
                            "clusterCaCertificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURDekNDQWZPZ0F3SUJBZ0lRR2txVDk3YWJsQkR5VEdyRXFCL2dIREFOQmdrcWhraUc5dzBCQVFzRkFEQXYKTVMwd0t3WURWUVFERXlRM05ERXhNalZpT0MwMk1qSXlMVFEwWm1VdFlUVXlNQzAyTWpKaE5EZ3haalV3WW1VdwpIaGNOTVRrd09ESXdNVGt3T0RRM1doY05NalF3T0RFNE1qQXdPRFEzV2pBdk1TMHdLd1lEVlFRREV5UTNOREV4Ck1qVmlPQzAyTWpJeUxUUTBabVV0WVRVeU1DMDJNakpoTkRneFpqVXdZbVV3Z2dFaU1BMEdDU3FHU0liM0RRRUIKQVFVQUE0SUJEd0F3Z2dFS0FvSUJBUUN4Kzd0d3RNUE1QTXNVeVpENzFQeTB3N3FMUTZRMUV3WGhMQkhSMWIwVApaZWZZSVRVZkdCOTNySVJDdnRYWkxhb2pKNjFpODFnZGxUNFZIRFFTNkJ6UGppaUM4aXhpMjdGUEp6cVRQeW5KCkdMeThGUnFhUm9CYjBOTVdjQnJwakZSR25CbzF5ZjNpYzEvNnZtcEd4SmU2L2NQd2UvbGR4MWlkOUVKa2g5RjkKa1hTSEsrM1F0MnJ2ZVdGdHQxYVdMWDBkblkreGVPRUZJNzdxYWVhWFVKQVJPekhzMDFtZitWT2VOOUd1d2lIMAorL2V3YmtEL2doN3RvS3VyTlR2c3RNR1hJWHNSajZWZi91Z2xsRmxKSm9iUWYzenR3MldLZjgxR3NMZ0pFeWo4CnR2K3pxTGRIV0pycHBMYnZQak4wTTMvVHFDK3drZ2FEVjdEMXJ5cVNmVHo5QWdNQkFBR2pJekFoTUE0R0ExVWQKRHdFQi93UUVBd0lDQkRBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCQgp2TktBRDdyOVgvT01xdVVtVmNmTDU2cmRsaVdEOGE2SXU4cWZUK0F1aXV1TWFBd05ReHVnZDc5MnhSdkJlN1B3CkY0czhxaXZxbTQvdXhXbERFWnUzUXpzMFhZcFdIVzlvYVNmb1lXRFNya3p0TEQ0U3ppb2pHWWNHWWZnNjNpVG0KV0toSjMrdTB1T0JLSXVaWU9ESUlJNzNUWGVpR1phdUxpTFlURWlrMHpwMzN6VjI5VGE3SXNGNXFaZ1cwWWRlWgpwbk92Z28wc1FwNlZzbkw0eUFLSWpvLzlkT1JMUmFZN1d3K2RTWTIxL0FPQllXWGNsc3krdzBHRHA1M09odXB1CkZxbElqbkZROXRrWldaMXpaS0ZoU0dhcE9oTVR6UHg3aDlFeFdlSkpGQkJyTUlTdHFJM3o3YTd2WWhBcUlRM1EKdFJITXhISW9WeUU1blhMTkxYaXgKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
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