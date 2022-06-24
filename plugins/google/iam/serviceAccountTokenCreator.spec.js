var expect = require('chai').expect;
var plugin = require('./serviceAccountTokenCreator');

const createCache = (err, data) => {
    return {
        projects: {
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            },
            get: {
                'global': {
                    data: [{ name: 'testproj' }]
                }
            }
        },
    }
};

describe('serviceAccountTokenCreator', function () {
    describe('run', function () {
        it('should give passing result if no iam policies are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM policies found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no user has the Service Account Token Creator role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No accounts have service account token creator roles');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXO8yOKJo=",
                        "bindings": [
                            {
                                "role": "roles/cloudbuild.builds.builder",
                                "members": [
                                    "serviceAccount:281330800462@cloudbuild.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/cloudbuild.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@gcp-sa-cloudbuild.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/compute.admin",
                                "members": [
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/compute.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@compute-system.iam.gserviceaccount.com"
                                ]
                            },
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if an account has service account token creator role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The account has a service account token creator role');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "version": 1,
                        "etag": "BwWXO8yOKJo=",
                        "bindings": [
                            {
                                "role": "roles/cloudbuild.builds.builder",
                                "members": [
                                    "serviceAccount:281330800462@cloudbuild.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/compute.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@compute-system.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": 'roles/iam.serviceAccountTokenCreator',
                                "members": [
                                    'serviceAccount:my-service-account@testproj.iam.gserviceaccount.com'
                                ]
                            }

                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
});