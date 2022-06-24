var expect = require('chai').expect;
var plugin = require('./memberAdmin');

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
                    data: [ { name: 'testproj' } ]
                }
            }
        },
    }
};

describe('memberAdmin', function () {
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

        it('should give passing result if no user has a primitive role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No accounts have primitive roles');
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
                            }
                        ]
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if a user has a primitive role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The account has the primitive role');
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
                                "role": "roles/editor",
                                "members": [
                                    "serviceAccount:2323462-compute@developer.gserviceaccount.com",
                                    "serviceAccount:2222222@cloudservices.gserviceaccount.com"
                                ]
                            },
                            {
                                "role": "roles/owner",
                                "members": [
                                    "user:john@right.com"
                                ]
                            },
                            {
                                "role": "roles/viewer",
                                "members": [
                                    "serviceAccount:rightservice@right-weather-281330.iam.gserviceaccount.com",
                                    "serviceAccount:mytest@right-weather-281330.iam.gserviceaccount.com"
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