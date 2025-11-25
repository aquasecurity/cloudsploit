var expect = require('chai').expect;
var auth = require('./appOrgnaizationalDirectoryAccess');
const apps = [
    {
        id: '2f4c228d-8d30-47a5-92ee-fb70bafa4bbc3',
        deletedDateTime: null,
        appId: '19a72cec-22a4-477c-a1db-fb70bafa4bbc3',
        applicationTemplateId: null,
        disabledByMicrosoftStatus: null,
        createdDateTime: '2023-03-19T03:21:07Z',
        displayName: 'test-app',
        description: null,
        publisherDomain: 'aquadeveloper.onmicrosoft.com',
        serviceManagementReference: null,
        signInAudience: 'AzureADMultipleOrgs'
    },
    {
        id: '2f4c228d-8d30-47a5-92ee-fb70bafa4bbc3',
        deletedDateTime: null,
        appId: '19a72cec-22a4-477c-a1db-fb70bafa4bbc3',
        applicationTemplateId: null,
        disabledByMicrosoftStatus: null,
        createdDateTime: '2023-03-19T03:21:07Z',
        displayName: 'test-app',
        description: null,
        publisherDomain: 'aquadeveloper.onmicrosoft.com',
        serviceManagementReference: null,
        signInAudience: 'AzureADMyOrg'
    }

]
const createCache = (err, data) => {
    return {
        applications: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('appOrgnaizationalDirectoryAccess', function() {
    describe('run', function() {
        it('should give passing result if no applications', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Entra ID applications found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });
        it('should give unknown result if unable to query for applications', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Entra ID applications:');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                {},
                null
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if application has multi tenant access', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Entra ID application has multi-tenant access enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(null,[apps[0]]);

            auth.run(cache, {}, callback);
        });

        it('should give passing result if application is accessible to single tenant only', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Entra ID application has single-tenant access enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(null,[apps[1]]);

            auth.run(cache, {}, callback);
        })
    })
})