var expect = require('chai').expect;
var automationAccountPrivateEndponits = require('./automationAcctPrivateEndpoints');

const automationAccounts = [
    {
        "id": "/subscriptions/12345/resourceGroups/DefaultResourceGroup-EUS/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2"
    }
];

const account = [
{
    "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2",
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
          "/subscriptions/12345/resourcegroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
            "PrincipalId": "123455",
            "ClientId": "1234554"
          }
        }
    },
    "privateEndpointConnections" :[
        {
            "id": '/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2/privateEndpointConnections/a112345',
            "name": 'a112345',
            "type": 'Microsoft.Automation/automationaccounts/privateEndponitConnections'
        }
    ]

},
{
    "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/Automate-12345-EUS2",
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
          "/subscriptions/12345/resourcegroups/test-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/testmeerab": {
            "PrincipalId": "123455",
            "ClientId": "1234554"
          }
        }
    }
}
]

const createCache = (automationAccounts,acct) => {
    let automationacct = {};
    let getacct = {};

    if (automationAccounts) {
        automationacct['data'] = automationAccounts;
        if (automationAccounts && automationAccounts.length) {
            getacct[automationAccounts[0].id] = {
                'data': acct
            };
        }
    }

    return {
        automationAccounts: {
            list: {
                'eastus': automationacct
            },
            get: {
                'eastus': getacct
            }
        }
    };
};

describe('automationAccountPrivateEndponits', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createCache([]);
            automationAccountPrivateEndponits.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createCache();
            automationAccountPrivateEndponits.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account has private endpoints configured', function (done) {
            const cache = createCache(automationAccounts, account[0]);
            automationAccountPrivateEndponits.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation Account has private endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account does not have private endpoints configured', function (done) {
            const cache = createCache(automationAccounts,account[1] );
            automationAccountPrivateEndponits.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation Account does not have private endpoints configured');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});