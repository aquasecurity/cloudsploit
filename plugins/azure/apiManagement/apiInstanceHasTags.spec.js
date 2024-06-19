var expect = require('chai').expect;
var apiInstanceHasTags = require('./apiInstanceHasTags.js');

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
        "tags": {},
        "location": "East US",
        "id": "/subscriptions/123456/resourceGroups/testfunction_group/providers/Microsoft.ApiManagement/service/test",
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
        "tags": {"key": "value"},
        "id": "/subscriptions/123456/resourceGroups/testfunction_group/providers/Microsoft.ApiManagement/service/test",
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

describe('apiInstanceHasTags', function () {
    describe('run', function () {

        it('should give pass result if No existing API Management service instances found', function (done) {
            const cache = createCache([]);
            apiInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing API Management instances found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query API Management service instances', function (done) {
            const cache = createCache(null, 'Error');
            apiInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query API Management instances');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if API Management service instances has tags associated', function (done) {
            const cache = createCache([apiManagementService[1]]);
            apiInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('API Management instance has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if API Management service instances does not have tags associated', function (done) {
            const cache = createCache([apiManagementService[0]]);
            apiInstanceHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API Management instance does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});