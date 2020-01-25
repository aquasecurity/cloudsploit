var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serviceAccountAdmin');

const createCache = (err, data, pdata) => {
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
                    err: err,
                    data: pdata
                }
            }
        },
    }
};

describe('serviceAccountAdmin', function () {
    describe('run', function () {
        it('should give passing result if no iam policies are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No IAM policies found.');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if the service accounts have least privilege', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('All service accounts have least access');
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
                                    "serviceAccount:367421934976@cloudbuild.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/cloudbuild.serviceAgent",
                                "members": [
                                    "serviceAccount:service-367421934976@gcp-sa-cloudbuild.iam.gserviceaccount.com"
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
                                    "serviceAccount:service-367421934976@compute-system.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/container.serviceAgent",
                                "members": [
                                    "serviceAccount:service-367421934976@container-engine-robot.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/editor",
                                "members": [
                                    "serviceAccount:367421934976-compute@developer.gserviceaccount.com",
                                    "serviceAccount:367421934976@cloudservices.gserviceaccount.com",
                                    "serviceAccount:right-weather-281330@appspot.gserviceaccount.com",
                                    "serviceAccount:service-367421934976@containerregistry.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/iam.serviceAccountUser",
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
                                    "serviceAccount:service-367421934976@service-networking.iam.gserviceaccount.com"
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
                                    "serviceAccount:service-367421934976@gcp-sa-websecurityscanner.iam.gserviceaccount.com"
                                ]
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if a service account has admin, owner or editor privileges', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The Service account has the following permissions');
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
                                    "serviceAccount:367421934976@cloudbuild.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/cloudbuild.serviceAgent",
                                "members": [
                                    "serviceAccount:service-367421934976@gcp-sa-cloudbuild.iam.gserviceaccount.com"
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
                                    "serviceAccount:service-367421934976@compute-system.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/container.serviceAgent",
                                "members": [
                                    "serviceAccount:service-367421934976@container-engine-robot.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/editor",
                                "members": [
                                    "serviceAccount:367421934976-compute@developer.gserviceaccount.com",
                                    "serviceAccount:367421934976@cloudservices.gserviceaccount.com",
                                    "serviceAccount:right-weather-281330@appspot.gserviceaccount.com",
                                    "serviceAccount:service-367421934976@containerregistry.iam.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/iam.serviceAccountUser",
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
                                    "serviceAccount:service-367421934976@service-networking.iam.gserviceaccount.com"
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
                                    "serviceAccount:service-367421934976@gcp-sa-websecurityscanner.iam.gserviceaccount.com"
                                ]
                            }
                        ],
                    },
                ],
                [
                    {
                        "id": "2813308004829045768",
                        "creationTimestamp": "2019-09-16T12:30:47.928-07:00",
                        "name": "right-weather-281330",
                        "commonInstanceMetadata": {
                            "fingerprint": "Nn0_urcZb1A=",
                            "kind": "compute#metadata"
                        },
                        "defaultServiceAccount": "367421934976-compute@developer.gserviceaccount.com",
                        "xpnProjectStatus": "UNSPECIFIED_XPN_PROJECT_STATUS",
                        "defaultNetworkTier": "PREMIUM",
                        "kind": "compute#project"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

    })
});