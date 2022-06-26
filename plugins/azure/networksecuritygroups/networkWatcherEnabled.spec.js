var expect = require('chai').expect;
var networkWatcherEnabled = require('./networkWatcherEnabled');

const networkWatchers = [
  {
    "name": "NetworkWatcher_eastus",
    "id": "/subscriptions/def1d0ac-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus",
    "etag": "W/\"a12bcd34-5333-4361-a645-0f110712c17e\"",
    "type": "Microsoft.Network/networkWatchers",
    "location": "eastus",
    "properties": {
      "provisioningState": "Succeeded",
      "runningOperationIds": []
    }
  },
  {
    "name": "NetworkWatcher_eastus2",
    "id": "/subscriptions/def1d0ac-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/NetworkWatcher_eastus2",
    "etag": "W/\"s31sde21-686a-449e-b678-1eb7bc38310e\"",
    "type": "Microsoft.Network/networkWatchers",
    "location": "eastus2",
    "properties": {
      "provisioningState": "Failed",
      "runningOperationIds": []
    }
  }
];

const virtualNetworks = [
    {
        "name": "aadds-vnet",
        "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Network/virtualNetworks/aadds-vnet",
        "etag": "W/\"9647a968-4864-4a13-a916-5cf7dd6fabff\"",
        "type": "Microsoft.Network/virtualNetworks",
        "location": "eastus",
        "provisioningState": "Succeeded",
        "resourceGuid": "e9502313-7cdc-400b-bd64-d97e361e63a4",
        "addressSpace": {
            "addressPrefixes": [
                "10.0.6.0/24"
            ]
        },
        "subnets": [
        {
            "name": "aadds-subnet",
            "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Network/virtualNetworks/aadds-vnet/subnets/aadds-subnet",
            "etag": "W/\"9647a968-4864-4a13-a916-5cf7dd6fabff\"",
            "properties": {
            "provisioningState": "Succeeded",
            "addressPrefix": "10.0.6.0/24",
            "networkSecurityGroup": {
                "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/akhtar-rg/providers/Microsoft.Network/networkSecurityGroups/aadds-nsg"
            },
            "delegations": [],
            "privateEndpointNetworkPolicies": "Enabled",
            "privateLinkServiceNetworkPolicies": "Enabled"
            },
            "type": "Microsoft.Network/virtualNetworks/subnets"
        }
        ],
        "virtualNetworkPeerings": [],
        "enableDdosProtection": false
    }
];

const createCache = (watchers, virtualNetworks) => {
    return {
        networkWatchers: {
            listAll: {
                'eastus': {
                    data: watchers
                }
            }
        },
        virtualNetworks: {
            listAll: {
                'eastus': {
                    data: virtualNetworks
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        networkWatchers: {
            listAll: {
                'eastus': {}
            }
        },
        virtualNetworks: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('networkWatcherEnabled', function() {
    describe('run', function() {
        it('should give passing result if no Virtual Networks or Network Watchers found', function(done) {
            const cache = createCache([], []);
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Virtual Networks or Network Watchers in the region');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Network Watchers', function(done) {
            const cache = createErrorCache();
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Network Watchers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for Virtual Networks', function(done) {
            const cache = createCache([], null);
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no Network Watchers found', function(done) {
            const cache = createCache([], [virtualNetworks[0]]);
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Network Watcher is not enabled in the region');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Network Watcher is enabled', function(done) {
            const cache = createCache([networkWatchers[0]], [virtualNetworks[0]]);
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Network Watcher is enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Network Watcher is not enabled', function(done) {
            const cache = createCache([networkWatchers[1]], [virtualNetworks[0]]);
            networkWatcherEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Network Watcher is not successfully provisioned for the region');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});