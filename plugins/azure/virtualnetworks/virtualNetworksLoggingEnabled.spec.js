var expect = require('chai').expect;
var virtualNetworksLoggingEnabled = require('./virtualNetworksLoggingEnabled');

const virtualNetworks = [
    {
        "name": 'test-vnet',
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet',
        "type": 'Microsoft.Network/virtualNetworks',
        "location": 'eastus',
        "provisioningState": 'Succeeded',
        "virtualNetworkPeerings": [],
        "enableDdosProtection": true
    }
];

const diagnosticSettings = [
    {
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'gio-test-setting',
        location: 'eastus',
        kind: null,
        tags: null,
        eventHubName: null,
        metrics: [],
        logs: [
        {
            category: 'NetworkSecurityGroupEvent',
            categoryGroup: null,
            enabled: true,
            retentionPolicy: [Object]
        },
        {
            category: 'NetworkSecurityGroupRuleCounter',
            categoryGroup: null,
            enabled: true,
            retentionPolicy: [Object]
        }
        ],
        logAnalyticsDestinationType: null
    },
    {
        id: '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Network/virtualNetworks/test-vnet/providers/microsoft.insights/diagnosticSettings/gio-test-setting',
        type: 'Microsoft.Insights/diagnosticSettings',
        name: 'gio-test-setting',
        location: 'eastus',
        kind: null,
        tags: null,
        identity: null,
        metrics: [],
        logs: [],
        logAnalyticsDestinationType: null
    },
];

const createCache = (vn, ds) => {
    const id = (vn && vn.length) ? vn[0].id : null;
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {
                    data: vn
                }
            }
        },
        diagnosticSettings: {
            listByVirtualNetworks: {
                'eastus': { 
                    [id]: { 
                        data: ds 
                    }
                }
            }

        },
    };
};

describe('virtualNetworksLoggingEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Virtual Network found', function(done) {
            const cache = createCache([], null);
            virtualNetworksLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for virtual networks', function(done) {
            const cache = createCache(null, null);
            virtualNetworksLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for diagnostic settings', function(done) {
            const cache = createCache([virtualNetworks[0]], null);
            virtualNetworksLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Network diagnostic settings');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if diagnostic logs enabled', function(done) {
            const cache = createCache([virtualNetworks[0]], [diagnosticSettings[0]]);
            virtualNetworksLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Virtual Network has diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if diagnostic logs not enabled', function(done) {
            const cache = createCache([virtualNetworks[0]], [diagnosticSettings[1]]);
            virtualNetworksLoggingEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Virtual Network does not have diagnostic logs enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});
