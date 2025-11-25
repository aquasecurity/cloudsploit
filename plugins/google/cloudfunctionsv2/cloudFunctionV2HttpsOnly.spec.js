var expect = require('chai').expect;
var plugin = require('./cloudFunctionV2HttpsOnly');


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
            "uri": "https://us-central1-my-test-project.cloudfunctions.net/function-1",
            "securityLevel": "SECURE_OPTIONAL"
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
            "uri": "https://us-central1-my-test-project.cloudfunctions.net/function-2",
            "securityLevel": "SECURE_ALWAYS"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-3",
        "environment": "GEN_2",
        "state": "ACTIVE",
        "updateTime": "2021-09-24T06:18:15.265Z",
        "buildConfig": {
            "runtime": "nodejs20",
            "entryPoint": "handleEvent"
        },
        "serviceConfig": {
            "serviceAccountEmail": "test@test-project.iam.gserviceaccount.com"
        }
    },
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-4",
        "environment": "GEN_1",
        "state": "ACTIVE",
        "runtime": "nodejs14",
        "httpsTrigger": {
            "url": "https://us-central1-my-test-project.cloudfunctions.net/function-4",
            "securityLevel": "SECURE_OPTIONAL"
        }
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

describe('httpTriggerRequireHttps', function () {
    describe('run', function () {
        it('should give passing result if no Cloud Functions V2 found', function (done) {
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

        it('should give passing result if Cloud Function is configured to require HTTPS for HTTP invocations', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud Function is configured to require HTTPS for HTTP invocations');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [functions[1]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Cloud Function is not configured to require HTTPS for HTTP invocations', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud Function is not configured to require HTTPS for HTTP invocations');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[0]],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Cloud Function trigger type is not HTTP', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud Function trigger type is not HTTP');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[2]],
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
                [functions[3]],
                null
            );

            plugin.run(cache, {}, callback);
        });

    })
});

