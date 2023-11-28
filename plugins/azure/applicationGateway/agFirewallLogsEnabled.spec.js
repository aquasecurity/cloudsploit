var expect = require('chai').expect;
var agFirewallLogsEnabled = require('./agFirewallLogsEnabled');

const appGateway = [
    {  
        "name": "meerab-test",
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourceGroups/meerab-rg/providers/Microsoft.Network/applicationGateways/meerab-test",
        "etag": "W/\"b3bb388c-f5ff-495a-8163-98edbeb32047\"",
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "tags": {},
        "provisioningState": "Succeeded",
        "resourceGuid": "c166b007-4ecd-45c2-9faa-74664407558b",
        "sku": {
          "name": "WAF_v2",
          "tier": "WAF_v2",
          "family": "Generation_1"
        },
    }
];

const diagnosticSettings = [
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/microsoft.network/applicationgateways/meerab-test/providers/microsoft.insights/diagnosticSettings/app-ds",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "app-ds",
        "logs": [
          {
            "category": "ApplicationGatewayAccessLog",
            "categoryGroup": null,
            "enabled": true,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          },
          {
            "category": "ApplicationGatewayFirewallLog",
            "categoryGroup": null,
            "enabled": true,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          }
        ],
        "logAnalyticsDestinationType": null
    },
    {},
    {
        "id": "/subscriptions/26a1a07e-06dd-4892-92c9-e4996b0fc546/resourcegroups/meerab-rg/providers/microsoft.network/applicationgateways/meerab-test/providers/microsoft.insights/diagnosticSettings/app-ds",
        "type": "Microsoft.Insights/diagnosticSettings",
        "name": "app-ds",
        "logs": [
          {
            "category": "ApplicationGatewayAccessLog",
            "categoryGroup": null,
            "enabled": false,
            "retentionPolicy": {
              "enabled": false,
              "days": 0
            }
          },
        ],
        "logAnalyticsDestinationType": null
    },
]
const createCache = (applicationGateway, diagnostics) => {
    let diagnostic = {};
    if (applicationGateway.length) {
        diagnostic[applicationGateway[0].id] = {
            data: diagnostics
        };
    }

    return {
        applicationGateway: {
            listAll: {
                'eastus': {
                    data: applicationGateway
                }
            }
        },
        diagnosticSettings: {
            listByApplicationGateways: {
                'eastus': diagnostic
            }
        }
    };
};

const createErrorCache = (key) => {
    if (key == 'appGateway') {
        return {
            applicationGateway: {
                listAll: {
                    'eastus': {}
                }
            }
        };
    } else if (key === 'noGateway'){
        return {
            applicationGateway: {
                listAll: {
                    'eastus': {
                        data:{}
                    }
                }
            }
        };
    }else if (key === 'diagnostic') {
        return {
            applicationGateway: {
                listAll: {
                    'eastus': {
                        data: [appGateway[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByApplicationGateways: {
                    'eastus': {}
                }
            }
        };
    } else {
        const appId = (appGateway && appGateway.length) ? appGateway[0].id : null;
        const diagnosticSetting = (diagnosticSettings && diagnosticSettings.length) ? diagnosticSettings[0].id : null;
        return {
            applicationGateway: {
                listAll: {
                    'eastus': {
                        data: [appId[0]]
                    }
                }
            },
            diagnosticSettings: {
                listByApplicationGateways: {
                    'eastus': {
                        data: {}
                    }
                }
            }
        };
    }
};

describe('agFirewallLogsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Application Gateway found', function(done) {
            const cache = createErrorCache('noGateway');
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Application Gateway found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result unable to query Application Gateway:', function(done) {
            const cache = createErrorCache('appGateway');
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Application Gateway');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });


        it('should give unknown result unable to query Application Gateway diagnostics settings:', function(done) {
            const cache = createErrorCache('diagnostic');
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Application Gateway diagnostics settings:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give pass result if no existing Application Gateway diagnostics settings found', function(done) {
            const cache = createCache([appGateway[0]],diagnosticSettings[1]);
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No existing Application Gateway diagnostics settings found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give pass result if Application Gateway firewall logs are enabled', function(done) {
            const cache = createCache([appGateway[0]],[diagnosticSettings[0]]);
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application Gateway firewall logs are enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give pass result if Application Gateway firewall logs are not enabled', function(done) {
            const cache = createCache([appGateway[0]],[diagnosticSettings[2]]);
            agFirewallLogsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application Gateway firewall logs are not enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

    });
}); 

