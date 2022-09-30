var expect = require('chai').expect;
var plugin = require('./topicLabelsAdded');

const topics = [
    {
        name: 'projects/testproj/topics/topic-1',
        labels: { label1: 'topic' },
    },
    {
        name: 'projects/testproj/topics/topic-2'
    }
];

const createCache = (err, data) => {
    return {
        topics: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('topicLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown result if a topic error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Pub/Sub topics');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no topics are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Pub/Sub topics found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if labels have been added to the topic', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for Pub/Sub topic');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [topics[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the topic', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Pub/Sub topic does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [topics[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})
