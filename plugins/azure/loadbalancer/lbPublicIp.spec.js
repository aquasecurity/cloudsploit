var expect = require('chai').expect;
var lbPublicIp = require('./lbPublicIp');

const loadBalancers = [
    {
        "name": "test",
        "id": "/subscriptions/123456/resourceGroups/test/providers/Microsoft.Network/loadBalancers/test",
        "etag": "W/\"1234\"",
        "type": "Microsoft.Network/loadBalancers",
        "location": "eastus",
        "sku": {
          "name": "Standard"
        },
        "provisioningState": "Succeeded",
        "resourceGuid": "123456",
        "frontendIPConfigurations": [
          {
            "name": "3859f556-a02d-42d9-8bd3-42301f41f8be",
            "id": "/subscriptions/1234/resourceGroups/test/providers/Microsoft.Network/loadBalancers/kubernetes/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be",
            "etag": "W/\"1234\"",
            "type": "Microsoft.Network/loadBalancers/frontendIPConfigurations",
            "properties": {
              "provisioningState": "Succeeded",
              "privateIPAllocationMethod": "Dynamic",
              "publicIPAddress": {
                "id": "/subscriptions/123456/resourceGroups/test/providers/Microsoft.Network/publicIPAddresses/3859f556-a02d-42d9-8bd3-42301f41f8be"
              },
              "inboundNatRules": [
                {
                  "id": "/subscriptions/123456/resourceGroups/test/providers/Microsoft.Network/loadBalancers/kubernetes/inboundNatRules/jbs"
                }
              ],
              "outboundRules": [
                {
                  "id": "/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/resourceGroups/MC_Ali-Resource-Group_test-ali_eastus/providers/Microsoft.Network/loadBalancers/kubernetes/outboundRules/aksOutboundRule"
                }
              ]
            }
          }
        ],

    },
    {
        "name": "test2",
        "id": "/subscriptions/123456/resourceGroups/testresource/providers/Microsoft.Network/loadBalancers/test2",
        "etag": "W/\"123456\"",
        "type": "Microsoft.Network/loadBalancers",
        "location": "eastus",
        "sku": {
          "name": "Standard"
        },
        "provisioningState": "Succeeded",
        "resourceGuid": "123456",
        "frontendIPConfigurations": [
          {
            "name": "3859f556-a02d-42d9-8bd3-42301f41f8be",
            "id": "/subscriptions/123456/resourceGroups/test/providers/Microsoft.Network/loadBalancers/kubernetes/frontendIPConfigurations/3859f556-a02d-42d9-8bd3-42301f41f8be",
            "etag": "W/\"123456\"",
            "type": "Microsoft.Network/loadBalancers/frontendIPConfigurations",
            "properties": {
                "privateIPAddress":'10.0.0.4',
                "privateIPAddressVersion":'IPv4',
                "privateIPAllocationMethod":'Dynamic',
                "provisioningState": 'Succeeded'
            }
          }
        ],

    }
];

const createCache = (lbs, err) => {
    return {
        loadBalancers: {
            listAll: {
                'eastus': {
                    err: err,
                    data: lbs
                }
            }
        }
    }
};

describe('lbPublicIp', function() {
    describe('run', function() {
        it('should give passing result if no existing Load Balancers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Load Balancers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            lbPublicIp.run(cache, {}, callback);
        });

        it('should give passing result if lb has Public IP associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Load Balancer is configured as public');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[0]]
            );

            lbPublicIp.run(cache, {}, callback);
        });

        it('should give failing result if lb does not have Public IP associated', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Load Balancer is not configured as public');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [loadBalancers[1]],
            );

            lbPublicIp.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query Load Balancers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Load Balancers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [],
                { message: 'Unable to query Load Balancers'}
            );

            lbPublicIp.run(cache, {}, callback);
        });
    })
});