var expect = require('chai').expect;
var plugin = require('./cloudFunctionV2LabelsAdded');


const functions = [
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-1",
        "environment": "GEN_2",
        "state": "ACTIVE",
        "updateTime": "2021-09-24T06:18:15.265Z",
        "buildConfig": {
            "runtime": "nodejs20",
            "entryPoint": "helloWorld"
        },
        "serviceConfig": {
            "serviceAccountEmail": "test@test-project.iam.gserviceaccount.com",
            "ingressSettings": "ALLOW_ALL"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-2",
        "environment": "GEN_2",
        "state": "ACTIVE",
        "updateTime": "2021-09-24T06:18:15.265Z",
        "buildConfig": {
            "runtime": "nodejs20",
            "entryPoint": "helloWorld"
        },
        "serviceConfig": {
            "serviceAccountEmail": "test@test-project.iam.gserviceaccount.com",
            "ingressSettings": "ALLOW_INTERNAL_AND_GCLB"
        },
        "labels": { 'deployment-tool': 'console-cloud', 'env': 'production' }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-3",
        "environment": "GEN_1",
        "state": "ACTIVE",
        "runtime": "nodejs14",
        "ingressSettings": "ALLOW_ALL"
    }
];

const createCache = (list, err) => {
    return {
        functionsv2: {
            list: {
                'us-central1': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('cloudFunctionLabelsAdded', function () {
    describe('run', function () {
        it('should give passing result if no Google Cloud functions found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Google Cloud functions found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Google Cloud functions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Google Cloud functions');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Cloud Function has labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for Cloud Function');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [functions[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Cloud Function does not have labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any labels');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should not check Gen 1 functions in v2 API response', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(0);
                done();
            };

            const cache = createCache(
                [functions[2]],
                null
            );

            plugin.run(cache, {}, callback);
        });

    })
});

