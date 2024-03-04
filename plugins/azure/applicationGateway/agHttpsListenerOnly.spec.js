var expect = require('chai').expect;
var agHttpsListenerOnly = require('./agHttpsListenerOnly');

const appGateway = [
    {   "sku": {
        "tier": "WAF_v2"
        },
        "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-gateway",',
        "type": "Microsoft.Network/applicationGateways",
        "httpListeners": [
            {
              "name": "listenerhttp",
              "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-app-gateway/httpListeners/listenerhttp",
              "etag": "W/\"9a09a0a2-7baa-44a2-b37b-88308429d799\"",
                "protocol": "Http",
                "hostNames": [],
                "requireServerNameIndication": false,
              "type": "Microsoft.Network/applicationGateways/httpListeners"
            },
            {
                "name": "listenerhttp2",
                "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-app-gateway/httpListeners/listenerhttp",
                "etag": "W/\"9a09a0a2-7baa-44a2-b37b-88308429d799\"",
                  "protocol": "Http",
                  "hostNames": [],
                  "requireServerNameIndication": false,
                "type": "Microsoft.Network/applicationGateways/httpListeners"
              },
              {
                "name": "listenerhttp3",
                "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-app-gateway/httpListeners/listenerhttp",
                "etag": "W/\"9a09a0a2-7baa-44a2-b37b-88308429d799\"",
                  "protocol": "Https",
                  "hostNames": [],
                  "requireServerNameIndication": false,
                "type": "Microsoft.Network/applicationGateways/httpListeners"
              }
          ],
    },
    {   
        "sku": {
        "tier": "WAF_v2"
        },
       "name": 'test-gateway',
        "id": '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test",',
        "type": "Microsoft.Network/applicationGateways",
        "location": "eastus",
        "httpListeners": [
            {
              "name": "listenerhttp",
              "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Network/applicationGateways/test-app-gateway/httpListeners/listenerhttp",
              "etag": "W/\"9a09a0a2-7baa-44a2-b37b-88308429d799\"",
                "protocol": "Https",
                "hostNames": [],
                "requireServerNameIndication": false,
              "type": "Microsoft.Network/applicationGateways/httpListeners"
            }
          ],
    },
];

const createCache = (gt) => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {
                    data: gt
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        applicationGateway: {
            listAll: {
                'eastus': {}
            }
        }
    };
};

describe('agHttpsListenerOnly', function() {
    describe('run', function() {
        it('should give passing result if no Application Gateway found', function(done) {
            const cache = createCache([]);
            agHttpsListenerOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Application Gateway found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if Application Gateway is using following non-https listeners', function(done) {
            const cache = createCache([appGateway[0]]);
            agHttpsListenerOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Application Gateway is using following non-https listeners: listenerhttp,listenerhttp2');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if Unable to query for Application Gateway', function(done) {
            const cache = createErrorCache();
            agHttpsListenerOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Application Gateway:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if Application Gateway is using https listeners only', function(done) {
            const cache = createCache([appGateway[1]]);
            agHttpsListenerOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Application Gateway is using https listeners only');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
        
    });
}); 

