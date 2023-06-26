var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./serviceAccountRole');

const createCache = (err, data, serviceAccErr, serviceAccData) => {
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
                    err: null,
                    data: [ { name: 'testproj' } ]
                }
            }
        },
        serviceAccounts: {
            list: {
                'global': {
                    err: serviceAccErr,
                    data: serviceAccData
                }
            }
        }
    }
};

const iamPolicies =  [
    {
        "version": 1,
        "etag": "BwWXO8yOKJo=",
        "bindings": [
            {
                "role": "roles/viewer",
                "members": [
                    "serviceAccount:testserviceacc@testservice-11111.iam.gserviceaccount.com",
                ]
            }
        ]
    }
]

const serviceAccounts = [
    {
        name: 'projects/test-proj/serviceAccounts/testserviceacc@testservice-11111.iam.gserviceaccount.com',
        projectId: 'test-proj',
        uniqueId: '111111111',
        email: 'testserviceacc@testservice-11111.iam.gserviceaccount.com',
        displayName: 'testacc1',
        etag: 'MDEwMjE5MjA=',
        description: 'Test Account',
        oauth2ClientId: '111111111'
      },
      {
        name: 'projects/test-proj/serviceAccounts/testaccw@test-proj.iam.gserviceaccount.com',
        projectId: 'test-proj',
        uniqueId: '111111111',
        email: 'testaccw@test-proj.iam.gserviceaccount.com',
        displayName: 'testaccw',
        etag: 'MDEwMjE5MjA=',
        description: 'Test Account',
        oauth2ClientId: '111111111'
      },
]

describe('serviceAccountRole', function () {
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

        it('should give unknown result if unable to query for iam policies', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for IAM Policies');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                {message: 'error'},
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no service accounts are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No service accounts found.');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                iamPolicies,
                null,
                []            
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for service accounts', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for service accounts');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                iamPolicies,
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        });


        it('should give passing result if service account has roles associated with it', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Service Account has one or more roles associated with it');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                iamPolicies,
                null,
                [serviceAccounts[0]]
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if service account does not have any role associated with it', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Service Account does not have any role associated with it');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                iamPolicies,
                null,
                [serviceAccounts[1]]
            );

            plugin.run(cache, {}, callback);
        });

    })
});