var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceMaintenanceBehavior');

const createCache = (instanceData, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
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

describe('instanceMaintenanceBehavior', function () {
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

        it('should fail if Instance Maintenance Behavior is not set to MIGRATE', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Maintenance Behavior is not set to MIGRATE');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "74374374",
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
                            "onHostMaintenance": "TERMINATE",
                            "automaticRestart": false,
                            "preemptible": false
                        }
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if Instance Maintenance Behavior is set to MIGRATE', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Instance Maintenance Behavior is set to MIGRATE');
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
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2",
                        "scheduling": {
                            "onHostMaintenance": "MIGRATE",
                            "automaticRestart": true,
                            "preemptible": false
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});