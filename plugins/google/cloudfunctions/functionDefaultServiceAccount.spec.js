var expect = require('chai').expect;
var plugin = require('./functionDefaultServiceAccount');


const functions = [
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-1",
        "status": "ACTIVE",
        "entryPoint": "helloWorld",
        "timeout": "60s",
        "availableMemoryMb": 256,
        "updateTime": "2021-09-24T06:18:15.265Z",
        "runtime": "nodejs14",
        "ingressSettings": "ALLOW_ALL",
        "serviceAccountEmail": "aqua@appspot.gserviceaccount.com"
      },
      {
        "name": "projects/my-test-project/locations/us-central1/functions/function-1",
        "status": "ACTIVE",
        "entryPoint": "helloWorld",
        "timeout": "60s",
        "availableMemoryMb": 256,
        "updateTime": "2021-09-24T06:18:15.265Z",
        "versionId": "1",
        "runtime": "nodejs14",
        "ingressSettings": "ALLOW_INTERNAL_AND_GCLB",
        "labels": { 'deployment-tool': 'console-cloud' },
        "serviceAccountEmail": "aqua-982@akhtar-dev-aqua.iam.gserviceaccount.com"
    
      }
];

const createCache = (list, err) => {
    return {
        functions: {
            list: {
                'us-central1': {
                    err: err,
                    data: list
                }
            }
        }
    }
};

describe('functionDefaultServiceAccount', function () {
    describe('run', function () {
        it('should give passing result if no cloud functions found', function (done) {
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
                expect(results[0].message).to.include('Unable to query for Google Cloud Functions');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if google cloud function is not using default service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud Function is not using default service account');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [functions[1]],
                null
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if google cloud function is using service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud Function is using default service account');
                expect(results[0].region).to.equal('us-central1');
                done();
            };

            const cache = createCache(
                [functions[0]],
                null            );

            plugin.run(cache, {}, callback);
        });

    })
});

