var expect = require('chai').expect;
var plugin = require('./persistentDisksAutoDelete');

const disks = [
    {
        "kind": "compute#disk",
        "id": "535353",
        "creationTimestamp": "2019-09-25T14:05:30.090-07:00",
        "name": "instance-3",
        "sizeGb": "10",
        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
        "status": "READY",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3"
    }
];
const createCache = (instanceData, error, disksData, disksErr) => {
    return {
        disks: {
            list: {
                'us-central1-a': {
                    data: disksData,
                    err: disksErr
                }
            }
        },
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

describe('persistentDisksAutoDelete', function () {
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
                null,
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
                null,
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });


        it('should fail if Auto Delete is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Auto Delete is enabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "2323",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "description": "",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": true,
                        "disks": [
                            {
                                "kind": "compute#attachedDisk",
                                "type": "PERSISTENT",
                                "mode": "READ_WRITE",
                                "source": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3",
                                "deviceName": "instance-3",
                                "index": 0,
                                "boot": true,
                                "autoDelete": true,
                                "licenses": [
                                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                                ],
                                "interface": "SCSI",
                                "guestOsFeatures": [
                                    {
                                        "type": "VIRTIO_SCSI_MULTIQUEUE"
                                    }
                                ]
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-3",
                    }
                ],
                null,
                disks,
                null

            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if Auto Delete is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Auto Delete is disabled');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "kind": "compute#instance",
                        "id": "2323",
                        "creationTimestamp": "2019-10-04T13:44:44.117-07:00",
                        "name": "instance-3",
                        "machineType": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/machineTypes/n1-standard-1",
                        "status": "RUNNING",
                        "zone": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a",
                        "canIpForward": true,
                        "disks": [
                            {
                                "kind": "compute#attachedDisk",
                                "type": "PERSISTENT",
                                "mode": "READ_WRITE",
                                "source": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/disks/instance-3",
                                "deviceName": "instance-3",
                                "index": 0,
                                "boot": true,
                                "autoDelete": false,
                                "licenses": [
                                    "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-9-stretch"
                                ],
                                "interface": "SCSI",
                                "guestOsFeatures": [
                                    {
                                        "type": "VIRTIO_SCSI_MULTIQUEUE"
                                    }
                                ]
                            }
                        ],
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/rosy-booth-253119/zones/us-central1-a/instances/instance-3",
                    }
                ],
                null,
                disks,
                null
            );


            plugin.run(cache, {}, callback);
        })

    })
});