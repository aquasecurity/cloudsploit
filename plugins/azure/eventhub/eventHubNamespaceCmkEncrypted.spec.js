var expect = require('chai').expect;
var eventHubNamespaceCmkEncrypted = require('./eventHubNamespaceCmkEncrypted');

const eventHubs = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "sku": {
            "name": "Premium",
            "tier": "Premium",
            "capacity": 1
        },
        "encryption": {
            "keySource": "Microsoft.KeyVault",
            "keyVaultProperties": [
              {
                "keyName": "test",
                "keyVaultUri": "https://hcicluster.vault.azure.net"
              }
            ],
            "requireInfrastructureEncryption": false
          }
    },
    {   
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "sku": {
            "name": "Premium",
            "tier": "Premium",
            "capacity": 1
        },
        "minimumTlsVersion": '1.1',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false,
    },
    {   
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "sku": {
            "name": "Basic",
            "tier": "basic",
            "capacity": 1
        },
    }
];

const createCache = (hub) => {
    return {
        eventHub: {
            listEventHub: {
                'eastus': {
                    data: hub
                }
            }
        }
    }
};

describe('eventHubNamespaceCmkEncrypted', function() {
    describe('run', function() {
        it('should give passing result if no event hub found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Event Hubs namespaces found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([]);
            eventHubNamespaceCmkEncrypted.run(cache, {}, callback);
        });

        it('should give failing result if Event Hubs namespace is not encrypted using CMK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace is not encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[1]]);
            eventHubNamespaceCmkEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if Event Hubs namespace is encrypted using CMK', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace is encrypted using CMK');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[0]]);
            eventHubNamespaceCmkEncrypted.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for event hubs', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Event Hubs namespaces:');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(null);
            eventHubNamespaceCmkEncrypted.run(cache, {}, callback);
        });

        it('should give passing result if event hub namespace is not premium namespace', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace is not a premium namespace');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[2]]);
            eventHubNamespaceCmkEncrypted.run(cache, {}, callback);
        });
    })
})