var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./integrityMonitoringEnabled');

const createCache = (err, data) => {
    return {
        clusters: {
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

describe('integrityMonitoringEnabled', function () {
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

        it('should give passing result if integrity monitoring is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Integrity Monitoring is enabled for all node pools');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-2",
                        "nodePools": [
                            {
                                "name": "default-pool",
                                "config": {
                                    "machineType": "n1-standard-1",
                                    "diskSizeGb": 100,
                                    "shieldedInstanceConfig": { 
                                        "enableIntegrityMonitoring": true 
                                    }
                                },
                                "initialNodeCount": 3,
                                "locations": [
                                    "us-central1-a"
                                ],
                                "status": "RUNNING"
                            }
                        ],
                        "locations": [
                            "us-central1-a"
                        ],
                        "zone": "us-central1-a",
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

        it('should give failing result if integrity monitoring is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Integrity Monitoring is disabled for these node pools');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-1",
                        "nodePools": [
                            {
                                "name": "default-pool",
                                "config": {
                                    "machineType": "n1-standard-1",
                                    "diskSizeGb": 100,
                                    "shieldedInstanceConfig": {}
                                },
                                "initialNodeCount": 3,
                                "locations": [
                                    "us-east1-b",
                                    "us-east1-c",
                                    "us-east1-d"
                                ],
                                "status": "RUNNING"
                            }
                        ],
                        "locations": [
                            "us-east1-b",
                            "us-east1-c",
                            "us-east1-d"
                        ],
                        "zone": "us-east1",       
                        "status": "RUNNING",
                        "currentNodeCount": 5,
                        "location": "us-east1"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})