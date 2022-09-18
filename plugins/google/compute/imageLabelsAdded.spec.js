var expect = require('chai').expect;
var plugin = require('./imageLabelsAdded');

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
        "labels": {"label-1": "test"},
        "kind": "compute#image"
    }
];
const createCache = (imageData, error) => {
    return {
        images: {
            list: {
                'global': {
                    data: imageData,
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

describe('imageLabelsAdded', function () {
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
                ['error']
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
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if disk image does not have any labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if labels are added for disk image', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for disk image');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [images[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });

    })
});