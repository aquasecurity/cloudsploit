var expect = require('chai').expect;
var plugin = require('./dnsLoggingEnabled');

const networks = [
    {
        "creationTimestamp": "2021-06-15T03:39:44.455-07:00",
        "name": "test-vpc",
        "description": "plugin vpc",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc",
        "autoCreateSubnetworks": false,
        "routingConfig": {
          "routingMode": "REGIONAL"
        },
        "mtu": 1460,
        "kind": "compute#network"
    },
    {
        "creationTimestamp": "2021-06-15T03:39:44.455-07:00",
        "name": "test-vpc-1",
        "description": "plugin vpc",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc-1",
        "autoCreateSubnetworks": false,
        "routingConfig": {
          "routingMode": "REGIONAL"
        },
        "mtu": 1460,
        "kind": "compute#network"
    },
];

const policies = [
    {
        "id": "7088602240669436579",
        "name": "test-policy",
        "enableInboundForwarding": true,
        "description": "abc",
        "networks": [
          {
            "networkUrl": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc",
            "kind": "dns#policyNetwork"
          }
        ],
        "enableLogging": true,
        "kind": "dns#policy"
      }
];

const createCache = (networks, networkErr, policies, policiesErr) => {
    return {
        networks: {
            list: {
                'global': {
                    err: networkErr,
                    data: networks
                }
            }
        },
        policies: {
            list: {
                'global': {
                    err: policiesErr,
                    data: policies
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'testProj'
                }
            }
        }
    }
};

describe('dnsLoggingEnabled', function () {
    describe('run', function () {
        it('should give unknown result if network error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query networks');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                ['error'],
            );
            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no network found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No networks found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [],
                null,
            );
            plugin.run(cache, {}, callback);
        });

        it('should give passing result if VPC Network has DNS logging enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VPC Network has DNS logging enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [networks[0]],
                null,
                policies
            );
            plugin.run(cache, {}, callback);
        });

        it('should give failing result if VPC Network does not have DNS logging enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VPC Network does not have DNS logging enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [networks[1]],
                null,
                policies
            );
            plugin.run(cache, {}, callback);
        });
    })
});