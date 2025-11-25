var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./instanceLeastPrivilege');

const createCache = (instanceData, error, iamPolicyData, defaultServiceAccount) => {
    return {
        compute: {
            list: {
                'us-central1-a': {
                    data: instanceData,
                    err: error
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [{
                        name: 'test-proj',
                        defaultServiceAccount: defaultServiceAccount || '123456789-compute@developer.gserviceaccount.com'
                    }]
                }
            },
            getIamPolicy: {
                'global': {
                    data: iamPolicyData || []
                }
            }
        }
    }
}

describe('instanceLeastPrivilege', function () {
    describe('run', function () {
        it('should return unknown if an instance error or no data returned', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.equal('Unable to query compute instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: []
            }];

            const cache = createCache(
                [],
                ['error'],
                iamPolicy,
                defaultSA
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

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: []
            }];

            const cache = createCache(
                [],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail when default service account has broad IAM role (editor)', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Service account has full access');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: [
                    {
                        role: 'roles/editor',
                        members: [
                            'serviceAccount:' + defaultSA
                        ]
                    }
                ]
            }];

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: defaultSA,
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass when default service account has restricted IAM roles', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('follows least privilege');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: [
                    {
                        role: 'roles/storage.objectViewer',
                        members: [
                            'serviceAccount:' + defaultSA
                        ]
                    }
                ]
            }];

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: defaultSA,
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail when custom service account has broad IAM role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Service account has full access');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const customSA = 'custom-sa@test-proj.iam.gserviceaccount.com';
            const iamPolicy = [{
                bindings: [
                    {
                        role: 'roles/editor',
                        members: [
                            'serviceAccount:' + customSA
                        ]
                    }
                ]
            }];

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: customSA,
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail when default service account has owner role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Service account has full access');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: [
                    {
                        role: 'roles/owner',
                        members: [
                            'serviceAccount:' + defaultSA
                        ]
                    }
                ]
            }];

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: defaultSA,
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail when default service account has admin role', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Instance Service account has full access');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const defaultSA = '123456789-compute@developer.gserviceaccount.com';
            const iamPolicy = [{
                bindings: [
                    {
                        role: 'roles/compute.admin',
                        members: [
                            'serviceAccount:' + defaultSA
                        ]
                    }
                ]
            }];

            const cache = createCache(
                [
                    {
                        name: 'instance-1',
                        description: '',
                        zone:
                            'https://www.googleapis.com/compute/v1/projects/lofty-advantage-242315/zones/us-central1-a',
                        serviceAccounts: [
                            {
                                email: defaultSA,
                                scopes: [
                                    'https://www.googleapis.com/auth/cloud-platform'
                                ]
                            }
                        ]
                    }
                ],
                null,
                iamPolicy,
                defaultSA
            );

            plugin.run(cache, {}, callback);
        })

    })
})
