var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./kmsUserSeparation');

const createCache = (err, data) => {
    return {
        projects: {
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            },
        },
    }
};

describe('kmsUserSeparation', function () {
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

        it('should give passing result if no user has the KMS admin role and a CryptoKey role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No accounts have a KMS admin role or a CryptoKey key role');
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
                            {
                                "role": "roles/container.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@container-engine-robot.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/editor",
                                "members": [
                                    "serviceAccount:281330800462-compute@developer.gserviceaccount.com",
                                    "serviceAccount:281330800462@cloudservices.gserviceaccount.com",
                                    "serviceAccount:right-weather-281330@appspot.gserviceaccount.com",
                                    "serviceAccount:service-281330800462@containerregistry.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/logging.privateLogViewer",
                                "members": [
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/owner",
                                "members": [
                                    "user:john@right.com"
                                ]
                            },
                            {
                                "role": "roles/servicenetworking.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@service-networking.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/viewer",
                                "members": [
                                    "serviceAccount:rightservice@right-weather-281330.iam.gserviceaccount.com",
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/websecurityscanner.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@gcp-sa-websecurityscanner.iam.gserviceaccount.com"
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if a user has the KMS admin role and  one or more CryptoKey roles', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The following accounts have the KMS admin role and one or more CryptoKey roles');
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
                                "role": "roles/compute.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@compute-system.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/container.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@container-engine-robot.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/editor",
                                "members": [
                                    "serviceAccount:281330800462-compute@developer.gserviceaccount.com",
                                    "serviceAccount:281330800462@cloudservices.gserviceaccount.com",
                                    "serviceAccount:right-weather-281330@appspot.gserviceaccount.com",
                                    "serviceAccount:service-281330800462@containerregistry.iam.gserviceaccount.com",
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/cloudkms.cryptoKeyDecrypter",
                                "members": [
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/cloudkms.admin",
                                "members": [
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/logging.privateLogViewer",
                                "members": [
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/owner",
                                "members": [
                                    "user:john@right.com"
                                ]
                            },
                            {
                                "role": "roles/servicenetworking.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@service-networking.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/viewer",
                                "members": [
                                    "serviceAccount:rightservice@right-weather-281330.iam.gserviceaccount.com",
                                    "serviceAccount:giotestservice111@right-weather-281330.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/websecurityscanner.serviceAgent",
                                "members": [
                                    "serviceAccount:service-281330800462@gcp-sa-websecurityscanner.iam.gserviceaccount.com"
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