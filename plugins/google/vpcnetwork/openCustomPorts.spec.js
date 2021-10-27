var expect = require('chai').expect;
var plugin = require('./openCustomPorts');


const firewalls = [
    {
        "id": "1111111",
        "creationTimestamp": "2021-05-07T12:10:19.939-07:00",
        "name": "default-allow-ssh",
        "description": "Allow SSH from anywhere",
        "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc",
        "priority": 65534,
        "sourceRanges": [
          "0.0.0.0/0"
        ],
        "allowed": [
          {
            "IPProtocol": "tcp",
            "ports": [
              "90"
            ]
          }
        ],
        "direction": "INGRESS",
        "logConfig": {
          "enable": false
        },
        "disabled": false,
        "kind": "compute#firewall"
      }, 
      {
        "id": "111111",
        "creationTimestamp": "2021-02-25T00:34:07.519-08:00",
        "name": "openall",
        "description": "Open All Ports",
        "network": "https://www.googleapis.com/compute/v1/projects/test-project/global/networks/test-vpc-1",
        "priority": 1000,
        "sourceRanges": [ "0.0.0.0/0" ],
        "allowed": [{ "IPProtocol": "tcp", "ports": [ "22" ]}],
        "direction": "INGRESS",
        "disabled": false,
        "kind": "compute#firewall"
      }
];

const createCache = (firewalls, firewallsErr) => {
    return {
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

describe('openCustomPorts', function () {
    describe('run', function () {
        it('should give unknown if unable to describe firewall rules', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query firewall rules');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                null,
                ['error'],
            );
            plugin.run(cache, { restricted_open_ports: 'tcp:80' }, callback);
        });

        it('should give passing result if no firewall rules found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No firewall rules found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [],
                null,
            );
            plugin.run(cache, {restricted_open_ports: 'tcp:80'}, callback);
        });

        it('should give passing result if VPC Network has no open custom ports', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No public open ports found');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [firewalls[0]],
                null
            );
            plugin.run(cache, {restricted_open_ports: 'tcp:80'}, callback);
        });

        it('should give failing result if VPC Network has open custom ports', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache(
                [firewalls[1]],
                null
            );
            plugin.run(cache, {restricted_open_ports: 'tcp:22'}, callback);
        });
    })
});