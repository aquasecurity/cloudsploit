var expect = require('chai').expect;
var plugin = require('./instanceDefaultServiceAccount');

const createCache = (instanceData, projectData, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
                }
            }
        },
        projects : {
            get: {
                'global': {
                    data: projectData
                }
            }
        }
    }
};

describe('instanceDefaultServiceAccount', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [
                    {
                        kind: "compute#project",
                        id: "00000111112222233333",
                        defaultServiceAccount: "779980017373-compute@developer.gserviceaccount.com",
                    }
                ],
                { message: 'error'}
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instances found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                [
                    {
                        kind: "compute#project",
                        id: "00000111112222233333",
                        defaultServiceAccount: "779980017373-compute@developer.gserviceaccount.com",
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if any compute instance is using the default service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Default service account is used for instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "1719867382827328572",
                        name: "testing-instance",
                        serviceAccounts: [
                            {
                              email: "779980017373-compute@developer.gserviceaccount.com",
                              scopes: [
                                "https://www.googleapis.com/auth/devstorage.read_only",
                                "https://www.googleapis.com/auth/logging.write",
                                "https://www.googleapis.com/auth/monitoring.write",
                                "https://www.googleapis.com/auth/servicecontrol",
                                "https://www.googleapis.com/auth/service.management.readonly",
                                "https://www.googleapis.com/auth/trace.append",
                              ],
                            },
                          ],
                    }
                ],
                [
                    {
                        kind: "compute#project",
                        id: "00000111112222233333",
                        defaultServiceAccount: "779980017373-compute@developer.gserviceaccount.com",
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if the compute instance is not using default service account', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Default service account is not used for instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "000001111112222222",
                        name: "testing-instance2",
                    }
                ],
                [
                    {
                        kind: "compute#project",
                        id: "00000111112222233333",
                        defaultServiceAccount: "779980017373-compute@developer.gserviceaccount.com",
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })
    })
})