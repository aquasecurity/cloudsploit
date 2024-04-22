var expect = require('chai').expect;
var automationAcctValidSourceControls = require('./validSourceControls.js');

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

const sourceControls = [
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/sourceControls/test-variable",
        "name": "testcontrol",
        "type": null,
        "creationTime": "2024-02-29T10:59:51.3432035+00:00",
        "lastModifiedTime": "2024-02-29T10:59:51.3432035+00:00",
        "repoUrl": "https://dummyrepo.git",
        "sourceType": "GitHub",
        "branch": "main",
        "folderPath": "/",
        "autoSync": false,
        "publishRunbook": false,
        "description": null

    },
    {
        "id": "/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.Automation/automationAccounts/test-automationacct/sourceControls/test-variable",
        "name": "testcontrol",
        "type": null,
        "creationTime": "2024-02-29T10:59:51.3432035+00:00",
        "lastModifiedTime": "2024-02-29T10:59:51.3432035+00:00",
        "repoUrl": "https://dummyrepo.git",
        "sourceType": "GitHub",
        "branch": "main",
        "folderPath": "/",
        "autoSync": false,
        "publishRunbook": false,
        "description": null

    },
    {},
]

const createCache = (automationAccounts, sourceControls) => {
    let source = {};
    if (automationAccounts.length) {
        source[automationAccounts[0].id] = {
            data: sourceControls
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
        sourceControls: {
            listByAutomationAccounts: {
                'eastus': source
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
    } else if (key === 'source') {
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            sourceControls: {
                listByAutomationAccounts: {
                    'eastus': {}
                }
            }
        };
    } else {
        const accountId = (automationAccounts && automationAccounts.length) ? automationAccounts[0].id : null;
        let variables = (sourceControls && sourceControls.length) ? sourceControls[0].id : null;
        let source = {};
        source[accountId] = {
                data: {}
            };
        
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            sourceControls: {
                listByAutomationAccounts: {
                    'eastus': source
                }
            }
        };
    }
};

describe('automationAcctValidSourceControls', function () {
    describe('run', function () {

        it('should give no result if setting value for default is empty', function (done) {
            const cache = createCache([automationAccounts[1]], [sourceControls[1]]);
            automationAcctValidSourceControls.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });


        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAcctValidSourceControls.run(cache, {automation_account_disallowed_source_controls: 'Github'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createErrorCache('unknownaccount');
            automationAcctValidSourceControls.run(cache,  {automation_account_disallowed_source_controls: 'Github'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give unknown result if Unable to query automation accounts source controls:', function (done) {
            const cache = createErrorCache('source');
            automationAcctValidSourceControls.run(cache,  {automation_account_disallowed_source_controls: 'Github'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation account source controls:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
       
        it('should give passing result if no source controls found', function (done) {
            const cache = createErrorCache('check');
            automationAcctValidSourceControls.run(cache, {automation_account_disallowed_source_controls: 'vsoGit'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts source controls found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account is using valid source controls', function (done) {
            const cache = createCache([automationAccounts[0]], [sourceControls[0]]);
            automationAcctValidSourceControls.run(cache, {automation_account_disallowed_source_controls: 'vsoGit'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account is using valid source controls');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account is using the undesired source controls:', function (done) {
            const cache = createCache([automationAccounts[1]], [sourceControls[1]]);
            automationAcctValidSourceControls.run(cache, {automation_account_disallowed_source_controls: 'Github'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account is using the following source controls: GitHub');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});