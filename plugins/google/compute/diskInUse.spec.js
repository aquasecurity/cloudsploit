var expect = require('chai').expect;
var plugin = require('./diskInUse');

const createCache = (diskData, error) => {
    return {
        disks: {
            list: {
                'us-central1-a': {
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

describe('diskInUse', function () {
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

        it('should fail if disk is not in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('not in use');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#disk",
                        "id": "11111",
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

        it('should pass if disk is in use', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('in use');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#disk",
                        "id": "1114",
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
                        "users": [
                            "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-2"
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
