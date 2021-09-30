var expect = require('chai').expect;
var plugin = require('./firewallLoggingMetadata');

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

const firewalls = [
    {
        id: '7656774017226387060',
        creationTimestamp: '2021-05-07T12:10:19.939-07:00',
        name: 'default-allow-ssh',
        description: 'Allow SSH from anywhere',
        network: 'https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc',
        priority: 65534,
        sourceRanges: [ '0.0.0.0/0' ],
        direction: 'INGRESS',
        logConfig: { enable: true},
        disabled: false,
        kind: 'compute#firewall'
      },
      {
        id: '7656774017226387060',
        creationTimestamp: '2021-05-07T12:10:19.939-07:00',
        name: 'default-allow-ssh',
        description: 'Allow SSH from anywhere',
        network: 'https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc-1',
        priority: 65534,
        sourceRanges: [ '0.0.0.0/0' ],
        direction: 'INGRESS',
        logConfig: { enable: true, metadata: 'INCLUDE_ALL_METADATA' },
        disabled: false,
        kind: 'compute#firewall'
      }
];

const createCache = (networks, networkErr, firewalls, firewallsErr) => {
    return {
        networks: {
            list: {
                'global': {
                    err: networkErr,
                    data: networks
                }
            }
        },
        firewalls: {
            list: {
                'global': {
                    err: firewallsErr,
                    data: firewalls
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

describe('firewallLoggingMetadata', function () {
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

        it('should give passing result if VPC Network does not have firewall metadata logging enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('VPC Network does not have firewall metadata logging enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [networks[0]],
                null,
                [firewalls[0]]
            );
            plugin.run(cache, {}, callback);
        });

        it('should give failing result if VPC Network has firewall metadata logging enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('VPC Network has firewall metadata logging enabled');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [networks[1]],
                null,
                [firewalls[1]]
            );
            plugin.run(cache, {}, callback);
        });
    })
});