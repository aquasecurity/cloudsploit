var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./dnsSecSigningAlgorithm');

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

describe('dnsSecSigningAlgorithm', function () {
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
        it('should give passing result if the managed zone does not have key signing using RSASHA1', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('RSASHA1 algorithm is not being for key signing');
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

        it('should give passing result if the managed zone does not have zone signing using RSASHA1', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[1].status).to.equal(0);
                expect(results[1].message).to.include('RSASHA1 algorithm is not being used for zone signing');
                expect(results[1].region).to.equal('global');
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

        it('should give failing result if the managed zone has key signing using RSASHA1', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('RSASHA1 algorithm is being used for key signing');
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
                                    "algorithm": "rsasha1",
                                    "keyLength": 2048,
                                    "kind": "dns#dnsKeySpec"
                                },
                                {
                                    "keyType": "zoneSigning",
                                    "algorithm": "rsasha1",
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

        it('should give failing result if the managed zone has zone signing using RSASHA1', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[1].status).to.equal(2);
                expect(results[1].message).to.include('RSASHA1 algorithm is being used for zone signing');
                expect(results[1].region).to.equal('global');
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
                                    "algorithm": "rsasha1",
                                    "keyLength": 2048,
                                    "kind": "dns#dnsKeySpec"
                                },
                                {
                                    "keyType": "zoneSigning",
                                    "algorithm": "rsasha1",
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