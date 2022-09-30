var expect = require('chai').expect;
var plugin = require('./datasetLabelsAdded');

const datasets = [
    {
        kind: 'bigquery#dataset',
        id: 'testproj:ds1',
        datasetReference: { datasetId: 'ds1', projectId: 'testproj' },
        labels: { dataset1: 'label' },
        location: 'us-central1'
    },
    {
        kind: 'bigquery#dataset',
        id: 'testproj:ds2',
        datasetReference: { datasetId: 'ds2', projectId: 'testproj' },
        labels: {},
        location: 'us-central1'
    }
];

const createCache = (err, data) => {
    return {
        datasets: {
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

describe('datasetLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown result if a dataset error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query BigQuery datasets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no datasets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No BigQuery datasets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if labels have been added to the dataset', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for BigQuery dataset');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasets[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the dataset', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('BigQuery dataset does not have any labels');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [datasets[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})