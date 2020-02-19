var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./webDashboardDisabled');

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

describe('webDashboardDisabled', function () {
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

        it('should give passing result if the web dashboard is disabled for the kubernetes cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The web dashboard is disabled for the Kubernetes cluster');
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
                            "clusterCaCertificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURERENDQWZTZ0F3SUJBZ0lSQU45TDJYVGNUZmFBS1ZxS1YwNGJhend3RFFZSktvWklodmNOQVFFTEJRQXcKTHpFdE1Dc0dBMVVFQXhNa1ltSm1NMlF3WmpNdE16SmxNeTAwT0RKa0xUaGlOR0V0WXpKbU5HTTVObUprT0RGagpNQjRYRFRFNU1EZ3lNREU1TWpFME5Gb1hEVEkwTURneE9ESXdNakUwTkZvd0x6RXRNQ3NHQTFVRUF4TWtZbUptCk0yUXdaak10TXpKbE15MDBPREprTFRoaU5HRXRZekptTkdNNU5tSmtPREZqTUlJQklqQU5CZ2txaGtpRzl3MEIKQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBNnh2UVpuK3YyeGZ3d2crR0lXT0Fjb0p2L24wQy9BczB6UXJXSWJoVgp3NDVRa2d4SW9nNmJGZVdBQkdiUHpTbnM5NlFMRUdYbDl3YUhvb081emZINVRwYzhOWkRyVmg0aS9mV3NiWHRSCjJvczNaSURCSStNai9rZmYra1Fjb3ZoMEc4YmxEUWRBaDVQbG1oYXpJS0FDdUFBZCtqRjJMTU96K3BvdHhkdWMKTEdXWmVQalBUWGxZaXFmQlQ0b3BubzhvN3FqRlo5WC93dkR6dlpyL3JIWGJVMGNmTm9SQ2p0RjRoMVVvU3V4OAp2NUNXN3Q1T1dDcUlSYjhNbDY0V3dZVmxxTDJRQ1FwWU9TMExEQ2JJTFB1LzdzSkFHN2t5SGk2SDU0TklESHl5CmJsMXhGeXFIV2cyNUlkVzhmbVhQK2Fkc0hiY3JvNDJWNmQvSkRNQzJCZG5PYXdJREFRQUJveU13SVRBT0JnTlYKSFE4QkFmOEVCQU1DQWdRd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQQpaQzNpdzFOb0YxK0xueWN6U2doakthcWkvQlRndzVxTlMxN3M1R2FVdEJ2OU4zenBMMHRMVzZuZHlmWTJ4MHZKCjlGK2hkOUhTTXEzT2JhZE9tM3JZODZYb1B3NG0vQS9iYm5QZ2IxbXN5aFJOd3BtNHhzMFhyM24xajZVZFhCUWIKbmNEdDdBU0hXMXQ2OWNqejFTYUhlR2VudFRubmFDOXpxWSsxZnI2QmNoSTNDZGJibW84NC9OOGZHZ1N6VjRYVAp5TkZzRXBRZ1Nvbnk3bHhMU2xqME8yb1Z4Z0YxK1E0VEp6cjRFS0xwVFpGTDltMmZ2b2xZZUNSKzIzMEVEQXM2ClNYOVpZdW9mMVlxaE44MnBNTnRsYUpOUkNRRlVDZ29UQ3Q2azZOdnVjWDZSdG5VN2F1eFoycUpRN3BibERReXcKbmtPc21EcWx3TjJCalhuWG4rOGRpQT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"
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
                                    "serviceAccount": "test1",
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

        it('should give failing result if the web dashboard is enabled for the kubernetes cluster', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The web dashboard is enabled for the Kubernetes cluster');
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
                                "disabled": false
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
                                    "autoUpgrade": false,
                                    "autoRepair": false
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
})