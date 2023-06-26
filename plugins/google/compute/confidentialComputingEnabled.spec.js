var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./confidentialComputingEnabled');

const createCache = (instanceData, error) => {
    return {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
                }
            },
        projects: {
            get: {
                'global': {
                    data: 'tets-proj'
                }
            }
        }
    }
};

describe('confidentialComputingEnabled', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query compute instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instances found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if Confidential Computing is disabled for the instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Confidential Computing is disabled for the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "3086667528957202900",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": true,
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-3",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": false,
                            "preemptible": false
                        },
                        "cpuPlatform": "Intel Haswell",
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "reservationAffinity": {
                            "consumeReservationType": "ANY_RESERVATION"
                        },
                        "displayDevice": {
                            "enableDisplay": false
                        }
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if Confidential Computing is enabled for the instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Confidential Computing is enabled for the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "1074579276103575670",
                        "creationTimestamp": "2019-09-25T14:05:30.014-07:00",
                        "name": "instance-2",
                        "description": "",
                        "tags": {
                            "fingerprint": "42WmSpB8rSM="
                        },
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/g1-small",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": false,
                        
                        "confidentialInstanceConfig": {
                            "enableConfidentialCompute": true
                        },
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": true,
                            "preemptible": false
                        },
                        "cpuPlatform": "Intel Haswell",
                        "labelFingerprint": "42WmSpB8rSM=",
                        "startRestricted": false,
                        "deletionProtection": false,
                        "reservationAffinity": {
                            "consumeReservationType": "ANY_RESERVATION"
                        },
                        "displayDevice": {
                            "enableDisplay": false
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});