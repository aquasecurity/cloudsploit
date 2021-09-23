var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./diskMultiAz');

const createCache = (diskData, error) => {
    return {
        disks: {
            aggregatedList: {
                'global': {
                    data: diskData,
                    err: error
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'test-proj'
                }
            }
        }
    }
};

describe('diskMultiAz', function () {
    describe('run', function () {
        it('should give unknown if unable to query compute disks', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query compute disks');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if No compute disks found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No disks found');
                expect(results[0].region).to.equal('regions/us-central1');
                done()
            };

            const cache = createCache(
                {
                    "regions/us-central1": {
                        "warning": {
                            "code": "NO_RESULTS_ON_PAGE",
                            "message": "There are no results for scope 'regions/us-central1' on this page.",
                            "data": [
                                {
                                    "key": "scope",
                                    "value": "regions/us-central1"
                                }
                            ]
                        }
                    }
                },
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if regional replication is not enabled for disk', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not enabled');
                expect(results[0].region).to.equal('zones/us-central1-a');
                done()
            };

            const cache = createCache(
                {
                    "zones/us-central1-a": {
                        "disks": [
                          {
                            "id": "1111111",
                            "creationTimestamp": "2021-09-23T13:26:18.565-07:00",
                            "name": "disk-2",
                            "sizeGb": "10",
                            "zone": "https://www.googleapis.com/compute/v1/projects/my-test-project/zones/us-central1-a",
                            "status": "READY",
                            "selfLink": "https://www.googleapis.com/compute/v1/projects/my-test-project/zones/us-central1-a/disks/disk-2",
                            "type": "https://www.googleapis.com/compute/v1/projects/my-test-project/zones/us-central1-a/diskTypes/pd-balanced",
                            "labelFingerprint": "42WmSpB8rSM=",
                            "physicalBlockSizeBytes": "4096",
                            "kind": "compute#disk"
                          }
                        ]
                      }
                },
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if regional replication is enabled for disk', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is enabled for');
                expect(results[0].region).to.equal('regions/us-central1');
                done()
            };

            const cache = createCache(
                {
                    "regions/us-central1": {
                        "disks": [
                            {
                                "id": "1111111",
                                "creationTimestamp": "2021-09-23T12:58:54.065-07:00",
                                "name": "disk-1",
                                "sizeGb": "10",
                                "status": "READY",
                                "selfLink": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-central1/disks/disk-1",
                                "type": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-central1/diskTypes/pd-balanced",
                                "labelFingerprint": "42WmSpB8rSM=",
                                "region": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-central1",
                                "replicaZones": [
                                    "https://www.googleapis.com/compute/v1/projects/my-test-project/zones/us-central1-a",
                                    "https://www.googleapis.com/compute/v1/projects/my-test-project/zones/us-central1-c"
                                ],
                                "physicalBlockSizeBytes": "4096",
                                "kind": "compute#disk"
                            }
                        ]
                    },
                }
            );

            plugin.run(cache, {}, callback);
        })

    })
});