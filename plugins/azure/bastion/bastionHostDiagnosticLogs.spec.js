var expect = require('chai').expect;
var bastionHostDiagnosticLogs = require('./bastionHostDiagnosticLogs');

const bastionHosts = [
    {
        "name": "bastionhost'",
        "id": "/subscriptions/subid/resourceGroups/rg1/providers/Microsoft.Network/bastionHosts/bastionhosttenant'",
        "type": "Microsoft.Network/bastionHosts",
        "location": "eastus",
        "sku": {
            "name": "Standard"
        }
    }
];

const diagnosticSettings = [
    {

        "id": "/subscriptions/subid/resourcegroups/rg1/providers/microsoft.network/bastionhosts/bastionhosttenant/providers/microsoft.insights/diagnosticSettings/testlogs",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "testlogs",
        "location": null,
        "kind": null,
        "tags": null,
        "storageAccountId": null,
        "serviceBusRuleId": null,
        "eventHubAuthorizationRuleId": null,
        "eventHubName": null,
        "metrics": [
            {
                "category": "AllMetrics",
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }
        ],
        "logs": [
            {
                "category": "BastionAuditLogs",
                "categoryGroup": null,
                "enabled": true,
                "retentionPolicy": {
                    "enabled": false,
                    "days": 0
                }
            }
        ],
        "logAnalyticsDestinationType": null,

        "identity": null
    }

];

const createCache = (bastionHosts, ds) => {
    const id = bastionHosts && bastionHosts.length ? bastionHosts[0].id : null;
    return {
        bastionHosts: {
            listAll: {
                'eastus': {
                    data: bastionHosts
                }
            }
        },
        diagnosticSettings: {
            listByBastionHosts: {
                'eastus': {
                    [id]: {
                        data: ds
                    }
                }
            }

        },
    };
};

const createErrorCache = () => {
    return {
        bastionHosts: {
            list: {
                'eastus': {}
            }
        }
    };
};

describe('bastionHostDiagnosticLogs', function () {
    describe('run', function () {

        it('should give unknown result if unable to query for azure bastion hosts', function (done) {
            const cache = createCache(null);
            bastionHostDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for bastion host:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if no bastion host exist', function (done) {
            const cache = createCache([]);
            bastionHostDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Bastion Hosts found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([bastionHosts[0]], null);
            bastionHostDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Bastion Host diagnostic settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Bastion Host has diagnostic logs enabled', function (done) {
            const cache = createCache([bastionHosts[0]], [diagnosticSettings[0]]);
            bastionHostDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Bastion Host has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Bastion Host does not have diagnostic logs enabled', function (done) {
            const cache = createCache([bastionHosts[0]],[[]]);
            bastionHostDiagnosticLogs.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Bastion Host does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});