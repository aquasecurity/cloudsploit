var expect = require('chai').expect;
var plugin = require('./vertexAIDatasetLabels');

const datasets = [
    {
        "name": 'projects/11111/locations/us-central1/datasets/33336',
        "displayName": 'untitled_2222',
        "metadataSchemaUri": 'gs://google-cloud-aiplatform/schema/dataset/metadata/text_1.0.0.yaml',
        "createTime": '2024-01-30T12:58:02.933220Z',
        "updateTime": '2024-01-31T06:45:38.630637Z',
        "etag": "bbbbb",
        "labels": { "test": 'test' },
        "dataItemCount": '40',
        "encryptionSpec": {
            "kmsKeyName": 'projects/test-dev/locations/us-central1/keyRings/test-kr/cryptoKeys/test-key-2'
        }
    },
    {
        "name": 'projects/11111/locations/us-central1/datasets/11111',
        "displayName": 'untitled_1101',
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
        "datasetSourceInfo": { "sourceType": 'AUTOML' }
    },
];


const createCache = (err, data) => {
    return {
        vertexAI: {
            listDatasets: {
                'us-central1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('vertexAIDatasetLabels', function () {
    describe('run', function () {
        it('should give unknown result if a dataset error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Vertex AI datasets');
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].message).to.include('No existing Vertex AI datasets found');
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].message).to.include('labels found for Vertex AI dataset');
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].message).to.include('Vertex AI dataset does not have any labels');
                expect(results[0].region).to.equal('us-central1');
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
