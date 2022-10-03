var expect = require('chai').expect;
var plugin = require('./bucketLabelsAdded');

const buckets = [
    {
        kind: 'storage#bucket',
        selfLink: 'https://www.googleapis.com/storage/v1/b/testproj-bucket-1',
        id: 'testproj-bucket-1',
        name: 'testproj-bucket-1',
        labels: { bucket: 'label' },
    },
    {
        kind: 'storage#bucket',
        selfLink: 'https://www.googleapis.com/storage/v1/b/testproj-bucket-2',
        id: 'testproj-bucket-2',
        name: 'testproj-bucket-2'    
    }
];

const createCache = (err, data) => {
    return {
        buckets: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('bucketLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown result if a bucket error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query storage buckets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no buckets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage buckets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if labels have been added to the bucket', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for storage bucket');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [buckets[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the bucket', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Storage bucket does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [buckets[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})
