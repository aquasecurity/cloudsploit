var expect = require('chai').expect;
var plugin = require('./functionAllUsersPolicy');

const createCache = (err, data, functionErr, functionData) => {
    return {
        functions: {
            list: {
                'us-central1': {
                    err: functionErr,
                    data: functionData
                }
            },
            getIamPolicy: {
                'us-central1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

const functions = [
    {
        "name": "projects/my-test-project/locations/us-central1/functions/function-1",
        "status": "ACTIVE",
        "entryPoint": "helloWorld",
        "timeout": "60s",
        "availableMemoryMb": 256,
        "updateTime": "2021-09-24T06:18:15.265Z",
        "runtime": "nodejs14",
        "ingressSettings": "ALLOW_ALL"
      },
      {
        "name": "projects/my-test-project/locations/us-central1/functions/function-2",
        "status": "ACTIVE",
        "entryPoint": "helloWorld",
        "timeout": "60s",
        "availableMemoryMb": 256,
        "updateTime": "2021-09-24T06:18:15.265Z",
        "versionId": "1",
        "runtime": "nodejs14",
        "ingressSettings": "ALLOW_INTERNAL_AND_GCLB",
        "labels": { 'deployment-tool': 'console-cloud' }
    
      }
];

describe('functionAllUsersPolicy', function () {
    describe('run', function () {
        it('should give unknown result if a function error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Google Cloud Functions');
                expect(results[0].region).to.equal('us-central1');
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
                expect(results[0].message).to.include('No Google Cloud functions found');
                expect(results[0].region).to.equal('us-central1');
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

        it('should give failing result if cloud function has anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cloud Function has anonymous or public access');
                expect(results[0].region).to.equal('us-central1');
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
                            "name": "projects/my-test-project/locations/us-central1/functions/function-1"
                        },
                        "etag": "CAE=",
                        "version": 1
                    }
                ],
                null,
                [functions[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if cloud function has anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cloud Function does not have anonymous or public access');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "parent": {
                            "name": "projects/my-test-project/locations/us-central1/functions/function-2"
                        },
                        "etag": "CAE=",
                        "version": 1
                    }
                ],
                null,
                [functions[1]]
            );

            plugin.run(cache, {}, callback);
        })
    })
});
