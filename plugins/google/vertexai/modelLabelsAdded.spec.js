var expect = require('chai').expect;
var plugin = require('./modelLabelsAdded');

const models = [
    {
        "name": 'projects/11111/locations/us-central1/models/3333333',
        "displayName": 'untitled_1706619456701',
        "supportedDeploymentResourcesTypes": ['AUTOMATIC_RESOURCES'],
        "supportedInputStorageFormats": ['jsonl'],
        "supportedOutputStorageFormats": ['jsonl'],
        "createTime": '2024-01-30T13:09:20.818657Z',
        "updateTime": '2024-01-31T06:06:12.979751Z',
        "etag": 'bbbbbbbbb',
        "versionId": '1',
        "versionAliases": ['default'],
        "versionCreateTime": '2024-01-30T13:09:20.818657Z',
        "versionUpdateTime": '2024-01-31T03:38:17.129540Z',
        "modelSourceInfo": { "sourceType": 'AUTOML' },
        "labels": {
            "test": 'test'
        }
    },
    {
        "name": 'projects/11111/locations/us-central1/models/11111',
        "displayName": 'untitled_1706619456701',
        "supportedDeploymentResourcesTypes": ['AUTOMATIC_RESOURCES'],
        "supportedInputStorageFormats": ['jsonl'],
        "supportedOutputStorageFormats": ['jsonl'],
        "createTime": '2024-01-30T13:09:20.818657Z',
        "updateTime": '2024-01-31T06:06:12.979751Z',
        "etag": 'bbbbbbbbb',
        "versionId": '1',
        "versionAliases": ['default'],
        "versionCreateTime": '2024-01-30T13:09:20.818657Z',
        "versionUpdateTime": '2024-01-31T03:38:17.129540Z',
        "modelSourceInfo": { "sourceType": 'AUTOML' }
    },
];

const createCache = (err, data) => {
    return {
        vertexAI: {
            listModels: {
                'us-central1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('modelLabelsAdded', function () {
    describe('run', function () {
        it('should give unknown result if a model error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Vertex AI models');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no models are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Vertex AI models found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if labels have been added to the model', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for Vertex AI model');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [models[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if no labels have been added to the model', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Vertex AI model does not have any labels');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [models[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
})
