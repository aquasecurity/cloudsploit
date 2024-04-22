var expect = require('chai').expect;
var automationAcctApprovedCerts = require('./automationAcctApprovedCerts.js');

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

const certificates = [
    {
        "id": "/subscriptions/1234/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/myAutomationAccount33/certificates/testCert",
        "name": "testCert",
        "description": "Sample Cert",
        "isExportable": false,
        "thumbprint": "thumbprint of cert",
        "expiryTime": "2018-03-29T17:25:45+00:00",
        "creationTime": "2017-03-29T17:26:43.337+00:00",
        "lastModifiedTime": "2017-03-29T17:28:55.01+00:00"
    },
    {

        "id": "/subscriptions/1234/resourceGroups/rg/providers/Microsoft.Automation/automationAccounts/myAutomationAccount33/certificates/testCert",
        "name": "testCert2",
        "description": "Sample Cert",
        "isExportable": false,
        "thumbprint": "thumbprint of cert",
        "expiryTime": "2018-03-29T17:25:45+00:00",
        "creationTime": "2017-03-29T17:26:43.337+00:00",
        "lastModifiedTime": "2017-03-29T17:28:55.01+00:00"

    }
   
]

const createCache = (automationAccounts, certs) => {
    let certificates = {};
    if (automationAccounts.length) {
        certificates[automationAccounts[0].id] = {
            data: certs
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
        certificates: {
            listByAutomationAccounts: {
                'eastus': certificates
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
    } else if (key === 'certs') {
        let certificates = {};
        if (automationAccounts.length) {
            certificates[automationAccounts[0].id] = {
                'err': 'unknown'
            };
        }
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            certificates: {
                listByAutomationAccounts: {
                    'eastus': certificates
                }
            }
        };
    } else {
        const accountId = (automationAccounts && automationAccounts.length) ? automationAccounts[0].id : null;
        const certificate = (certificates && certificates.length) ? certificates[0].id : null;
        return {
            automationAccounts: {
                list: {
                    'eastus': {
                        data: [automationAccounts[0]]
                    }
                }
            },
            certificates: {
                listByAutomationAccounts: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('automationAcctApprovedCerts', function () {
    describe('run', function () {
        it('should give no result if setting is not enabled', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAcctApprovedCerts.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should give pass result if No existing automation accounts found', function (done) {
            const cache = createErrorCache('noaccounts');
            automationAcctApprovedCerts.run(cache, {ca_approved_certificates: 'cert'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Automation accounts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation accounts:', function (done) {
            const cache = createErrorCache('unknownaccount');
            automationAcctApprovedCerts.run(cache, {ca_approved_certificates: 'cert'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query automation certs', function (done) {
            const cache = createErrorCache('certs');
            automationAcctApprovedCerts.run(cache, {ca_approved_certificates: 'cert'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Automation accounts certificates');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if automation account has approved certificates', function (done) {
            const cache = createCache([automationAccounts[0]], [certificates[0]]);
            automationAcctApprovedCerts.run(cache, {ca_approved_certificates: 'testCert, appCert'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Automation account is using approved certificates only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if automation account is using following certificates which are not approved by organization: ', function (done) {
            const cache = createCache([automationAccounts[1]], [certificates[1]]);
            automationAcctApprovedCerts.run(cache, {ca_approved_certificates: 'testCert, appCert'}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Automation account is using following unapproved certificates: testCert2');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});