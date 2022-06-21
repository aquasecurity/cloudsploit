var expect = require('chai').expect;
var plugin = require('./publicDiskImages');

const imagePolicies = [
    {
        "version": 1,
        "etag": "BwXZ3RM6WFs=",
        "bindings": [
            {
                "role": "roles/compute.imageUser",
                "members": [
                    "allUsers",
                ]
            },
        ],
        "parent": {
            "id": "1231",
            "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
            "name": "image-1",
            "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-1",
            "sourceDiskId": "4476293856257965646",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-1",

            "kind": "compute#image"
        }
    },
    {
        "version": 1,
        "etag": "BwXZ3RM6WFs=",
        "bindings": [
            {
                "role": "roles/compute.imageUser",
                "members": [
                    "myserviceaccount@gmail.com",
                ]
            },
        ],
        "parent":  {
            "id": 1232,
            "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
            "name": "image-2",
            "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-2",
            "sourceDiskId": "4476293856257965646",
            "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-2",
            "kind": "compute#image"
        }
    }
]
const images = [
    {
        "id": "1231",
        "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
        "name": "image-1",
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-1",
        "sourceDiskId": "4476293856257965646",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-1",
        "kind": "compute#image"
    },
    {
        "id": 1232,
        "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
        "name": "image-2",
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-2",
        "sourceDiskId": "4476293856257965646",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-2",
        "kind": "compute#image"
    },
    {
        "id": "1233",
        "creationTimestamp": "2022-03-09T16:05:01.878-08:00",
        "name": "image-3",
        "sourceDisk": "https://www.googleapis.com/compute/v1/projects/test-proj/zones/us-central1-a/disks/disk-3",
        "sourceDiskId": "4476293856257965646",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-proj/global/images/image-3",
        "kind": "compute#image"
    }
];
const createCache = (imageData, error, policyData, policyErr) => {
    return {
        images: {
            list: {
                'global': {
                    data: imageData,
                    err: error
                }
            },
            getIamPolicy: {
                'global': {
                    data: policyData,
                    err: policyErr

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

describe('publicDiskImages', function () {
    describe('run', function () {

        it('should give unknown if unable to query disk images', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Disk Images');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error'],
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no disk images found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Disk Images found');
                expect(results[0].region).to.equal('global');
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

        it('should give unknown if unable to query IAM Policies for disk images', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query IAM Policies for Disk Images');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                images,
                null,
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no IAM Policies found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM Policies found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                images,
                null,
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if disk image is publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Disk Image is publicly accessible');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[0]],
                null,
                [imagePolicies[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if no IAM policies are found for disk image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM Policies found for disk image');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[2]],
                null,
                [imagePolicies],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if disk image is not publicly accessible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Disk Image is not publicly accessible');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[1]],
                null,
                [imagePolicies[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });
    })
});