var expect = require('chai').expect;
var eventHubLocalAuthDisabled = require('./eventHubLocalAuthDisabled');

const eventHubs = [
    {
        "kind": "v12.0",
        "location": "eastus",
        "tags": {},
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.EventHub/namespaces/testHub'",
        "name": "testHub",
        "type": 'Microsoft.EventHub/Namespaces',
        "location": 'East US',
        "tags": {},
        "minimumTlsVersion": '1.2',
        "publicNetworkAccess": 'Disabled',
        "disableLocalAuth": true,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false
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
        "minimumTlsVersion": '1.1',
        "publicNetworkAccess": 'Enabled',
        "disableLocalAuth": false,
        "zoneRedundant": true,
        "isAutoInflateEnabled": false,
        "maximumThroughputUnits": 0,
        "kafkaEnabled": false,
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

describe('eventHubLocalAuthDisabled', function() {
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
            eventHubLocalAuthDisabled.run(cache, {}, callback);
        });

        it('should give failing result if event hub has local auth enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Event Hubs namespace has local authentication enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[1]]);
            eventHubLocalAuthDisabled.run(cache, {}, callback);
        });

        it('should give passing result if eventHub has local auth disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Event Hubs namespace has local authentication disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache([eventHubs[0]]);
            eventHubLocalAuthDisabled.run(cache, {}, callback);
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
            eventHubLocalAuthDisabled.run(cache, {}, callback);
        });
    })
})