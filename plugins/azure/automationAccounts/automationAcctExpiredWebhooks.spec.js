var expect = require('chai').expect;
var automationAcctExpiredWebhooks = require('./automationAcctExpiredWebhooks');
var nextMonthExpiry = new Date();
nextMonthExpiry.setMonth(nextMonthExpiry.getMonth() + 1);

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

const webhooks = [
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/webhooks/test1",
        "name": "test1",
        "creationTime": "2024-01-22T13:33:52.1066667+00:00",
        "expiryTime": nextMonthExpiry,
    },
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/webhooks/test2",
        "name": "test2",
        "creationTime": "2024-01-22T13:33:52.1066667+00:00",
        "expiryTime": "2024-02-22T13:33:52.1066667+00:00",

    },
    {},
]
const createCache = (automationAccounts, webhooks) => {
    let webhook = {};
    if (automationAccounts.length) {
        webhook[automationAccounts[0].id] = {
            data: webhooks
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
        webhooks: {
            listByAutomationAccounts: {
                'eastus': webhook
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
                        data: []
                    }
                }
            }
        };
    } else if (key === 'webhook') {
        return {
            automationAccounts: {
                list: {
                    'global': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            webhooks: {
                listByAutomationAccounts: {
                    'global': {}
                }
            }
        };
    } else {
        const accountId = (automationAccounts && automationAccounts.length) ? automationAccounts[0].id : null;
        const webhook = (webhooks && webhooks.length) ? webhooks[0].id : null;
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            webhooks: {
                listByAutomationAccounts: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};


describe('automationAcctExpiredWebhooks', function () {
    describe('run', function () {

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAcctExpiredWebhooks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createErrorCache('unknownaccount');
            automationAcctExpiredWebhooks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation account  webhooks', function (done) {
            const cache = createErrorCache('policy');
            automationAcctExpiredWebhooks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Automation account webhooks: ');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if webhook is vaild', function (done) {
            const cache = createCache([automationAccounts[0]], [webhooks[0]]);
            automationAcctExpiredWebhooks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account webhook is valid');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if webhook is expired', function (done) {
            const cache = createCache([automationAccounts[1]], [webhooks[1]]);
            automationAcctExpiredWebhooks.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account webhook has expired');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});