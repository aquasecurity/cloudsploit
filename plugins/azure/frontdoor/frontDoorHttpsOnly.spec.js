var expect = require('chai').expect;
var frontDoorHttpsOnly = require('./frontDoorHttpsOnly.js');

const classicFrontDoors = [
   {
    id: '/subscriptions/1234567890/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoors/aquatest',
      type: 'Microsoft.Network/frontdoors',
      name: 'aquatest',
      location: 'Global',
      tags: {},
      routingRules: [
        {
            "id": "/subscriptions/1234567890/resourcegroups/meerab-rg/providers/Microsoft.Network/Frontdoors/aquatest/RoutingRules/test-instance",
            "name": "test-instance",
            "type": "Microsoft.Network/Frontdoors/RoutingRules",
            "properties": {
              "routeConfiguration": {
                "redirectType": "Moved",
                "redirectProtocol": "HttpsOnly",
              },
              "resourceState": "Enabled",
              "acceptedProtocols": [
                "Http"
              ]
            }
          },
          {
            "id": "/subscriptions/1234567890/resourcegroups/meerab-rg/providers/Microsoft.Network/Frontdoors/aquatest/RoutingRules/rule2",
            "name": "rule2",
            "type": "Microsoft.Network/Frontdoors/RoutingRules",
            "properties": {
              "routeConfiguration": {
                "redirectType": "Found",
                "redirectProtocol": "HttpOnly",
              },
              "acceptedProtocols": [
                "Https"
              ],
            }
          }
      ]
   },
   {
    id: '/subscriptions/1234567890/resourcegroups/meerab-rg/providers/Microsoft.Network/frontdoors/aquatest',
      type: 'Microsoft.Network/frontdoors',
      name: 'aquatest',
      location: 'Global',
      tags: {},
      routingRules: [
          {
            "id": "/subscriptions/1234567890/resourcegroups/meerab-rg/providers/Microsoft.Network/Frontdoors/aquatest/RoutingRules/rule2",
            "name": "rule2",
            "type": "Microsoft.Network/Frontdoors/RoutingRules",
            "properties": {
              "routeConfiguration": {
                "redirectType": "Found",
                "redirectProtocol": "HttpOnly",
              },
              "acceptedProtocols": [
                "Https"
              ],
            }
          }
      ]
   }
];

const createCache = (classicFrontDoors) => {
    return {
        classicFrontDoors: {
            list: {
                'global': {
                    data: classicFrontDoors
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        classicFrontDoors: {
            list: {
                'global': {
                    data:{}
                }
            }
        }
    };
};
describe('frontDoorHttpsOnly', function () {
    describe('run', function () {

        it('should give pass result if no classic Front Door profiles found', function (done) {
            const cache = createErrorCache();
            frontDoorHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing Front Door profiles found');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give pass result if classic Front Door profile is configured to use Https only', function (done) {
            const cache = createCache([classicFrontDoors[0]]);
            frontDoorHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Front Door profile is configured to use HTTPS only');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

        it('should give fail result if classic Front Door profile is not configured to use Https only', function (done) {
            const cache = createCache([classicFrontDoors[1]]);
            frontDoorHttpsOnly.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Front Door profile is not configured to use HTTPS only');
                expect(results[0].region).to.equal('global');
                done();
            });
        });

    });
});