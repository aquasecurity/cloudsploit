var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./shieldedNodes');

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

describe('shielded Nodes', function () {
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
        })
        it('should PASS if no clusters are found', function (done) {
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
        })
        it('should PASS if shielded nodes is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Shielded Nodes feature is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-2",
                        "subnetwork": "default",
                        "locations": [
                            "us-central1-a"
                        ],
                        "privateCluster": true,
                        "masterIpv4CidrBlock": "10.127.0.0/28",
                        "defaultMaxPodsConstraint": {
                            "maxPodsPerNode": "110"
                        },
                        "databaseEncryption": {
                            "state": "DECRYPTED"
                        },
                        "shieldedNodes": {"enabled": true},
                        "tierSettings": {
                            "tier": "STANDARD"
                        },
                        "zone": "us-central1-a",
                        "status": "RUNNING",
                        "servicesIpv4Cidr": "10.70.0.0/20",
                        "currentNodeCount": 3,
                        "location": "us-central1-a"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
        it('should FAIL if shielded nodes is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Shielded Nodes feature is not enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "standard-cluster-2",
                        "subnetwork": "default",
                        "locations": [
                            "us-central1-a"
                        ],
                        "privateCluster": true,
                        "masterIpv4CidrBlock": "10.127.0.0/28",
                        "defaultMaxPodsConstraint": {
                            "maxPodsPerNode": "110"
                        },
                        "databaseEncryption": {
                            "state": "DECRYPTED"
                        },
                        "shieldedNodes": {},
                        "tierSettings": {
                            "tier": "STANDARD"
                        },
                        "zone": "us-central1-a",
                        "status": "RUNNING",
                        "servicesIpv4Cidr": "10.70.0.0/20",
                        "currentNodeCount": 3,
                        "location": "us-central1-a"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
})