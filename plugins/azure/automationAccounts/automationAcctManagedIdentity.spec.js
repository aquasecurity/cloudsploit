var expect = require('chai').expect;
var automationAccountManagedIdentity = require('./automationAcctManagedIdentity.js');

const automationAccounts = [
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-EUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2",
        "location": "EastUS2",
        "name": "Automate-12345-EUS2",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
          "creationTime": "2023-10-27T07:27:02.76+00:00",
          "lastModifiedTime": "2023-10-27T07:27:02.76+00:00"
        },
        "identity": {
            "type": "systemassigned,userassigned",
            "principalId": "dc03d47d-e6df-491f-aebe-50a93412a890",
            "tenantId": "d207c7bd-fcb1-4dd3-855a-cfd2f9b651e8",
            "userAssignedIdentities": {
              "/subscriptions/12345/resourcegroups/meerab-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
                "PrincipalId": "123455",
                "ClientId": "1234554"
              }
            }
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-CUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-CUS",
        "location": "centralus",
        "name": "Automate-12345-CUS",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
          "creationTime": "2023-07-17T13:09:21.4866667+00:00",
          "lastModifiedTime": "2023-07-17T13:09:21.4866667+00:00"
        }
    }
];

const createCache = (automationAccounts,err) => {
    return {
        automationAccounts: {
            list: {
                'eastus': {
                    data: automationAccounts,
                    err: err
                }
            }
        }
    }
};

describe('automationAccountManagedIdentity', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createCache([]);
            automationAccountManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createCache(null, 'Error');
            automationAccountManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account has managed identity enabled', function (done) {
            const cache = createCache([automationAccounts[0]]);
            automationAccountManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account does not have managed identity enabled', function (done) {
            const cache = createCache([automationAccounts[1]]);
            automationAccountManagedIdentity.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account does not have managed identity enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});