var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./csekEncryptionEnabled');

const createCache = (instanceData, error) => {
    return {
        disks: {
            aggregatedList: {
                'global': {
                    data: instanceData,
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

describe('csekEncryptionEnabled', function () {
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
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No compute disks found');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if CSEK Encryption is disabled for disk', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('CSEK Encryption is disabled for disk');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                {
                    "regions/us-east1": {
                        "disks": [
                            {
                                "id": "1111111",
                                "creationTimestamp": "2021-09-23T12:58:54.065-07:00",
                                "name": "disk-1",
                                "sizeGb": "10",
                                "status": "READY",
                                "selfLink": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1/disks/disk-1",
                                "type": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1/diskTypes/pd-balanced",
                                "labelFingerprint": "42WmSpB8rSM=",
                                "region": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1",
                                "physicalBlockSizeBytes": "4096",
                                "kind": "compute#disk"
                            }
                        ]
                    },
                }
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if CSEK Encryption is enabled for disk', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('CSEK Encryption is enabled for disk');
                expect(results[0].region).to.equal('us-east1');
                done()
            };

            const cache = createCache(
                {
                    "regions/us-east1": {
                        "disks": [
                            {
                                "id": "1111111",
                                "creationTimestamp": "2021-09-23T12:58:54.065-07:00",
                                "name": "disk-1",
                                "sizeGb": "10",
                                "status": "READY",
                                "selfLink": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1/disks/disk-1",
                                "type": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1/diskTypes/pd-balanced",
                                "labelFingerprint": "42WmSpB8rSM=",
                                "region": "https://www.googleapis.com/compute/v1/projects/my-test-project/regions/us-east1",
                                "physicalBlockSizeBytes": "4096",
                                "kind": "compute#disk",
                                "diskEncryptionKey": {
                                    'key': 'true',
                                }
                            }
                        ]
                    },
                }
            );

            plugin.run(cache, {}, callback);
        })

    })
});