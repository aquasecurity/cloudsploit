var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dnsSecEnabled');

const createCache = (err, data) => {
    return {
        managedZones: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('dnsSecEnabled', function () {
    describe('run', function () {
        it('should give unknown result if a managed zone error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query DNS managed zones');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no managed zone records are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No DNS managed zones found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if the managed zone has dns sec enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The managed zone has DNS security enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "giotestdnszone1",
                        "dnsName": "cloudsploit.com.",
                        "description": "",
                        "id": "4534388710135378441",
                        "nameServers": [
                            "ns-cloud-e1.googledomains.com.",
                            "ns-cloud-e2.googledomains.com.",
                            "ns-cloud-e3.googledomains.com.",
                            "ns-cloud-e4.googledomains.com."
                        ],
                        "creationTime": "2019-10-03T21:11:18.894Z",
                        "dnssecConfig": {
                            "state": "on",
                            "defaultKeySpecs": [
                                {
                                    "keyType": "keySigning",
                                    "algorithm": "rsasha256",
                                    "keyLength": 2048,
                                    "kind": "dns#dnsKeySpec"
                                },
                                {
                                    "keyType": "zoneSigning",
                                    "algorithm": "rsasha256",
                                    "keyLength": 1024,
                                    "kind": "dns#dnsKeySpec"
                                }
                            ],
                            "nonExistence": "nsec3",
                            "kind": "dns#managedZoneDnsSecConfig"
                        },
                        "visibility": "public",
                        "kind": "dns#managedZone"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if the managed zone does not have dns sec enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The managed zone does not have DNS security enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "name": "giotestdnszone1",
                        "dnsName": "cloudsploit.com.",
                        "description": "",
                        "id": "4534388710135378441",
                        "nameServers": [
                            "ns-cloud-e1.googledomains.com.",
                            "ns-cloud-e2.googledomains.com.",
                            "ns-cloud-e3.googledomains.com.",
                            "ns-cloud-e4.googledomains.com."
                        ],
                        "creationTime": "2019-10-03T21:11:18.894Z",
                        "dnssecConfig": {
                            "state": "off",
                            "defaultKeySpecs": [
                                {
                                    "keyType": "keySigning",
                                    "algorithm": "rsasha256",
                                    "keyLength": 2048,
                                    "kind": "dns#dnsKeySpec"
                                },
                                {
                                    "keyType": "zoneSigning",
                                    "algorithm": "rsasha256",
                                    "keyLength": 1024,
                                    "kind": "dns#dnsKeySpec"
                                }
                            ],
                            "nonExistence": "nsec3",
                            "kind": "dns#managedZoneDnsSecConfig"
                        },
                        "visibility": "public",
                        "kind": "dns#managedZone"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});