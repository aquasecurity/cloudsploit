var expect = require('chai').expect;
var plugin = require('./topicAllUsersPolicy');

const createCache = (err, data, topicErr, topicData) => {
    return {
        topics: {
            list: {
                'global': {
                    err: topicErr,
                    data: topicData
                }
            },
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

const topics = [
    {
        name: 'projects/testproj/topics/topic-1',
    },
    {
        name: 'projects/testproj/topics/topic-2'
    }
];

describe('topicAllUsersPolicy', function () {
    describe('run', function () {
        it('should give unknown result if a topic error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Pub/Sub topics');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                null,
                ['error'],
                null
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
                null,
                null,
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if topic has anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Pub/Sub topic has anonymous or public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "bindings": [
                            { "role": 'roles/editor', "members": ['allUsers'] },
                            {
                                "role": 'roles/viewer',
                                "members": [
                                    'allAuthenticatedUsers',
                                    'allUsers',
                                ]
                            }
                        ],
                        "parent": {
                            "name": "projects/testproj/topics/topic-1"
                        },
                        "etag": "CAE=",
                        "version": 1
                    }
                ],
                null,
                [topics[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if topic has anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Pub/Sub topic does not have anonymous or public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "parent": {
                            "name": "projects/testproj/topics/topic-2"
                        },
                        "etag": "CAE=",
                        "version": 1
                    }
                ],
                null,
                [topics[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
});