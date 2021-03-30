var expect = require('chai').expect;
var multipleSubnets = require('./multipleSubnets');

const listVnets = [
    {
        "name": "cloudsplit-vnet",
        "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet",
        "type": "Microsoft.Network/virtualNetworks",
        "subnets": [
          {
            "name": "default",
            "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet/subnets/default",
            "type": "Microsoft.Network/virtualNetworks/subnets"
          },
          {
            "name": "default1",
            "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet/subnets/default",
            "type": "Microsoft.Network/virtualNetworks/subnets"
          }
        ]
    },
    {
        "name": "cloudsplit-vnet",
        "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet",
        "type": "Microsoft.Network/virtualNetworks",
        "subnets": [
          {
            "name": "default",
            "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet/subnets/default",
            "type": "Microsoft.Network/virtualNetworks/subnets"
          }
        ]
    },
    {
        "name": "cloudsplit-vnet",
        "id": "/subscriptions/123/resourceGroups/aqua-rg/providers/Microsoft.Network/virtualNetworks/cloudsplit-vnet",
        "type": "Microsoft.Network/virtualNetworks",
        "subnets": []
    }
];

const createCache = (vnets, err) => {
    return {
        virtualNetworks: {
            listAll: {
                'eastus': {
                    err: err,
                    data: vnets
                }
            }
        }
    }
};

describe('multipleSubnets', function() {
    describe('run', function() {
        it('should give passing result if No existing Virtual Networks found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Virtual Networks found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            multipleSubnets.run(cache, {}, callback);
        });

        it('should give failing result if only one subnet in the Virtual Network is used', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Only one subnet in the Virtual Network is used');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listVnets[1]]
            );

            multipleSubnets.run(cache, {}, callback);
        });

        it('should give passing result if there are more than one subnets in Virtual Network', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('different subnets used in the Virtual Network');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listVnets[0]]
            );

            multipleSubnets.run(cache, {}, callback);
        });

        it('should give passing result if the Virtual Network does not have any subnets', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The Virtual Network does not have any subnets');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                [listVnets[2]]
            );

            multipleSubnets.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for Virtual Networks', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Virtual Networks');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                listVnets,
                { message: 'unable to query Virtual Networks'}
            );

            multipleSubnets.run(cache, {}, callback);
        });
    })
})