var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./deprecatedImages');

const createCache = (instanceData, error, diskData, diskError) => {
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
        images: {
            list: {
                "global": {
                    "data": [
                        {
                            "id": '11511',
                            "creationTimestamp": '2021-10-09T05:58:36.754-07:00',
                            "name": 'image-1',
                            "sourceType": 'RAW',
                            "deprecated": { state: 'DEPRECATED' },
                            "status": 'READY',
                            "diskSizeGb": '10',
                            "sourceDisk": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/disk-1',
                            "sourceDiskId": '11111',
                            "selfLink": 'https://www.googleapis.com/compute/v1/projects/my-project/global/images/image-1',
                            "storageLocations": [ 'us-central1' ],
                            "kind": 'compute#image'
                        },
                        {
                            "id": '11611',
                            "creationTimestamp": '2021-10-09T05:58:36.754-07:00',
                            "name": 'image-2',
                            "sourceType": 'RAW',
                            "status": 'READY',
                            "diskSizeGb": '10',
                            "sourceDisk": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/disk-1',
                            "sourceDiskId": '11111',
                            "selfLink": 'https://www.googleapis.com/compute/v1/projects/my-project/global/images/image-2',
                            "storageLocations": [ 'us-central1' ],
                            "kind": 'compute#image'
                        },
                    ]
                }
            }
        },
        disks: {
            list: {
                'us-central1-a': {
                    data: diskData,
                    err: diskError
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
const diskData = [
    {
        "id": '5678',
        "creationTimestamp": '2021-10-09T06:10:38.389-07:00',
        "name": 'instance-2',
        "sizeGb": '10',
        "zone": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a',
        "status": 'READY',
        "selfLink": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/instance-2',
        "sourceImage": 'https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-10-buster-v20210916',
        "sourceImageId": '11611',
        "physicalBlockSizeBytes": '4096',
        "kind": 'compute#disk'
      },
      {
        "id": '1234',
        "creationTimestamp": '2021-10-09T05:59:46.571-07:00',
        "name": 'instance-1',
        "sizeGb": '10',
        "zone": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a',
        "status": 'READY',
        "selfLink": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/instance-1',
        "sourceImage": 'https://www.googleapis.com/compute/v1/projects/my-project/global/images/image-2',
        "sourceImageId": '11511',
        "kind": 'compute#disk'
      }
]
describe('deprecatedImages', function () {
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
                ['error'],
                null,
                diskData,
                null
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
                null,
                diskData,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if instance is created from a deprecated image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance is created from a deprecated image');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": '1111111',
                        "creationTimestamp": '2021-10-09T05:59:46.533-07:00',
                        "name": 'instance-1',
                        "machineType": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/machineTypes/e2-micro',
                        "status": 'RUNNING',
                        "zone": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a',
                        "canIpForward": false,
                        "disks": [
                          {
                            "type": 'PERSISTENT',
                            "mode": 'READ_WRITE',
                            "source": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/instance-1',
                            "deviceName": 'instance-1',
                            "index": 0,
                            "boot": true,
                            "autoDelete": true,
                            "interface": 'SCSI',
                            "diskSizeGb": '10',
                            "kind": 'compute#attachedDisk'
                          }
                        ],
                        "kind": 'compute#instance'
                      }
                ],
                null,
                diskData,
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if instance is not created from a deprecated image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('Instance is not created from a deprecated image');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": '1111',
                        "creationTimestamp": '2021-10-09T06:10:38.352-07:00',
                        "name": 'instance-2',
                        "disks": [
                          {
                            "type": 'PERSISTENT',
                            "mode": 'READ_WRITE',
                            "source": 'https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/disks/instance-2',
                            "deviceName": 'instance-2',
                            "index": 0,
                            "boot": true,
                            "autoDelete": true,
                            "diskSizeGb": '10',
                            "kind": 'compute#attachedDisk'
                          }
                        ],
                        "kind": 'compute#instance'
                      }
                ],
                null,
                diskData,
                null
            );

            plugin.run(cache, {}, callback);
        })

    })
});