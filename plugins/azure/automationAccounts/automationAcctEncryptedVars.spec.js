var expect = require('chai').expect;
var automationAcctEncryptedVariables = require('./automationAcctEncryptedVars.js');

const automationAccounts = [
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct",
        "location": "EastUS2",
        "name": "test-automationacct",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
            "creationTime": "2023-10-27T07:27:02.76+00:00",
            "lastModifiedTime": "2023-10-27T07:27:02.76+00:00"
        }
    },
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct",
        "location": "centralus",
        "name": "test-automationacct",
        "type": "Microsoft.Automation/AutomationAccounts",
        "tags": {},
        "properties": {
            "creationTime": "2023-07-17T13:09:21.4866667+00:00",
            "lastModifiedTime": "2023-07-17T13:09:21.4866667+00:00"
        }
    }
];

const accountVariables = [
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/variables/test-variable",
        "name": "test-variable",
        "type": "Microsoft.Automation/AutomationAccounts/Variables",
        "creationTime": "2024-01-22T13:33:52.1066667+00:00",
        "lastModifiedTime": "2024-01-22T13:33:52.1066667+00:00",
        "isEncrypted": true,
        "description": "test"

    },
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/variables/test-variable",
        "name": "test-variable",
        "type": "Microsoft.Automation/AutomationAccounts/Variables",
        "creationTime": "2024-01-22T13:33:52.1066667+00:00",
        "lastModifiedTime": "2024-01-22T13:33:52.1066667+00:00",
        "isEncrypted": false,
        "description": "test"

    },
    {},
]

const createCache = (automationAccounts, variables) => {
    let variable = {};
    if (automationAccounts.length) {
        variable[automationAccounts[0].id] = {
            data: variables
        };
    }


    return {
        automationAccounts: {
            list: {
                'eastus': {
                    data: automationAccounts
                }
            }
        },
        accountVariables: {
            listByAutomationAccounts: {
                'eastus': variable
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'unknownaccount') {
        return {
            automationAccounts: {
                list: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'noaccounts') {
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    } else if (key === 'variable') {
        return {
            automationAccounts: {
                list: {
                    'global': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            accountVariables: {
                listByAutomationAccounts: {
                    'global': {}
                }
            }
        };
    } else {
        const accountId = (automationAccounts && automationAccounts.length) ? automationAccounts[0].id : null;
        const variables = (accountVariables && accountVariables.length) ? accountVariables[0].id : null;
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            accountVariables: {
                listByAutomationAccounts: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('automationAcctEncryptedVariables', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAcctEncryptedVariables.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createErrorCache('unknownaccount');
            automationAcctEncryptedVariables.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation account variables', function (done) {
            const cache = createErrorCache('policy');
            automationAcctEncryptedVariables.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation account variables:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account has all variables encrypted', function (done) {
            const cache = createCache([automationAccounts[0]], [accountVariables[0]]);
            automationAcctEncryptedVariables.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account has all variables encrypted');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account does not have all variables encrypted', function (done) {
            const cache = createCache([automationAccounts[1]], [accountVariables[1]]);
            automationAcctEncryptedVariables.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account has following unencrypted variables: test');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});