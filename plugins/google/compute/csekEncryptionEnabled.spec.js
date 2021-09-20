var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./csekEncryptionEnabled');

const createCache = (instanceData, error) => {
    return {
        disks: {
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
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#disk",
                        "id": "5472446060006107254",
                        "creationTimestamp": "2019-09-25T14:05:30.090-07:00",
                        "name": "instance-2",
                        "sizeGb": "10",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "status": "READY",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-2",
                        "sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20190916",
                        "sourceImageId": "2382294996946296915",
                        "type": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/diskTypes/pd-standard",
                        "licenses": [
                            "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                        ],
                        "guestOsFeatures": [
                            {
                                "type": "VIRTIO_SCSI_MULTIQUEUE"
                            }
                        ],
                        "lastAttachTimestamp": "2019-09-25T14:05:30.090-07:00",
                        "users": [
                            "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2"
                        ],
                        "labelFingerprint": "42WmSpB8rSM=",
                        "licenseCodes": [
                            "1000205"
                        ],
                        "physicalBlockSizeBytes": "4096"
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if CSEK Encryption is enabled for disk', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('CSEK Encryption is enabled for disk');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#disk",
                        "id": "5472446060006107254",
                        "creationTimestamp": "2019-09-25T14:05:30.090-07:00",
                        "name": "instance-2",
                        "sizeGb": "10",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "status": "READY",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-2",
                        "sourceImage": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-9-stretch-v20190916",
                        "sourceImageId": "2382294996946296915",
                        "type": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/diskTypes/pd-standard",
                        "licenses": [
                            "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                        ],
                        "guestOsFeatures": [
                            {
                                "type": "VIRTIO_SCSI_MULTIQUEUE"
                            }
                        ],
                        "lastAttachTimestamp": "2019-09-25T14:05:30.090-07:00",
                        "users": [
                            "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2"
                        ],
                        "labelFingerprint": "42WmSpB8rSM=",
                        "licenseCodes": [
                            "1000205"
                        ],
                        "physicalBlockSizeBytes": "4096",
                        "diskEncryptionKey": {
                            'key': 'true',
                        }
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});