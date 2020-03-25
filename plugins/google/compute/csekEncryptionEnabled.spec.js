var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./csekEncryptionEnabled');

const createCache = (instanceData, instanceDatab, error) => {
    return {
        disks: {
            list: {
                'us-central1-a': {
                    data: instanceData,
                    err: error
                },
                'us-central1-b': {
                    data: instanceDatab,
                    err: error
                },
                'us-central1-c': {
                    data: instanceDatab,
                    err: error
                },
                'us-central1-f': {
                    data: instanceDatab,
                    err: error
                }
            }
        }
    }
};

describe('csekEncryptionEnabled', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(3);
                expect(results[4].message).to.include('Unable to query disks');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                ['null']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.include('No disks found in the region');
                expect(results[4].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail csek encryption is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(2);
                expect(results[4].message).to.include('CSEK Encryption is disabled for the following disks');
                expect(results[4].region).to.equal('us-central1');
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
                [],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass with block project-wide ssh key', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(1);
                expect(results[4].status).to.equal(0);
                expect(results[4].message).to.equal('CSEK Encryption is enabled for all disks in the region');
                expect(results[4].region).to.equal('us-central1');
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