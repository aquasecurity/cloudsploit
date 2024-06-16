var expect = require('chai').expect;
var apiInstanceManagedIdentity = require('./apiInstanceManagedIdentity.js');

const apiManagementService = [
    {
        "etag": "AAAAAAGIUI4=",
        "publisherEmail": "dummy.@aquasec.com",
        "publisherName": "dummy",
        "notificationSenderEmail": "apimgmt-noreply@mail.windowsazure.com",
        "provisioningState": "Succeeded",
        "targetProvisioningState": "",
        "identity": null,
        "zones": null,
        "location": "East US",
        "tags": {},
        "id": "/subscriptions/123456/resourceGroups/fatima-testfunction_group/providers/Microsoft.ApiManagement/service/meerab",
        "name": "meerab",
        "type": "Microsoft.ApiManagement/service"
    },
    {
        "etag": "AAAAAAGIUI4=",
        "publisherEmail": "dummy.@aquasec.com",
        "publisherName": "dummy",
        "notificationSenderEmail": "apimgmt-noreply@mail.windowsazure.com",
        "provisioningState": "Succeeded",
        "targetProvisioningState": "",
        "identity": {
        "type": "SystemAssigned",
        "principalId": "fdd1f197-d0e0-4d04-a5ef-9dbb654afd14",
        "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8"
      },
        "zones": null,
        "location": "East US",
        "tags": {},
        "id": "/subscriptions/123456/resourceGroups/fatima-testfunction_group/providers/Microsoft.ApiManagement/service/meerab",
        "name": "meerab",
        "type": "Microsoft.ApiManagement/service"
    }
];

const createCache = (apiManagementService, err) => {
    return {
        apiManagementService: {
            list: {
                'eastus': {
                    data: apiManagementService,
                    err: err
                }
            }
        }
    }
};

describe('apiInstanceManagedIdentity', function () {
    describe('run', function () {

        it('should give pass result if No existing API Management service instances found', function (done) {
            const cache = createCache([]);
            apiInstanceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing API Management instances found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query API Management service instances:', function (done) {
            const cache = createCache(null, 'Error');
            apiInstanceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query API Management instances:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if API Management service instances has managed identity enabled', function (done) {
            const cache = createCache([apiManagementService[1]]);
            apiInstanceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('API Management service instance has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if API Management service instances does not have managed identity enabled', function (done) {
            const cache = createCache([apiManagementService[0]]);
            apiInstanceManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API Management service instance does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});