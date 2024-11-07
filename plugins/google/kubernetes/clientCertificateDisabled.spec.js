var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./clientCertificateDisabled');

const createCache = (err, data) => {
    return {
        kubernetes: {
                list: {
                    'global': {
                        err: err,
                        data: data
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('clientCertificateDisabled', function () {
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

        it('should give passing result if client certificates are not used for cluster authentication', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cluster is not using');
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
                            "clientCaCertificate": "sdsdsdaLSd0tLS1CRUdJTiBDRVJUSUZJQ0t3aalV3WW1VdwpItLSSSSSS0tLQo=",
                        },
                        "binaryAuthorization": { 
                            "evaluationMode": 'PROJECT_SINGLETON_POLICY_ENFORCE' 
                        },
                        
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

        it('should give failing result if client certifcate is used for cluster authentication', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cluster is using');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-1",
                        "binaryAuthorization": { 
                            "evaluationMode": 'DISABLED' 
                        },
                        "masterAuth": {
                            "clientCaCertificate": "sdsdsdaLSd0tLS1CRUdJTiBDRVJUSUZJQ0t3aalV3WW1VdwpItLSSSSSS0tLQo=",
                            "clientCertificate": "AHDHAB6GDGDGSTKKXNCNSHHSODSSDDFF1==",
                            "clientKey": "RSVADJDKSLDSMD2242HDHDHDDLA"
                        },
                        "loggingService": "none",
                        "monitoringService": "none",
                        "network": "default",
                        "clusterIpv4Cidr": "10.48.0.0/14",
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