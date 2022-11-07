var expect = require('chai').expect;
var plugin = require('./bigtableInstanceLabelsAdded');

const instances = [
    {
        name: 'projects/testproj/instances/test-1',
        displayName: 'test-1',
        state: 'READY',
        type: 'PRODUCTION',
        labels: { 'label': 'label' },
        createTime: '2022-10-15T22:02:43.720541615Z'
    },
    {
        name: 'projects/testproj/instances/test-2',
        displayName: 'test-2',
        state: 'READY',
        type: 'PRODUCTION',
        createTime: '2022-10-15T22:02:43.720541615Z'
    },

];

const createCache = (err, data) => {
    return {
            bigtable: {
                list: {
                    'global': {
                        err: err,
                        data: data
                    }
                }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('bigtableInstanceLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown result if an instance error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query BigTable instances');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no bigtable instances are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No BigTable instances found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if labels have been added to the instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for BigTable instance');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [instances[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the instance', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('BigTable instance does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [instances[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})