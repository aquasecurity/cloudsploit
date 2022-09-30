var expect = require('chai').expect;
var plugin = require('./dnsZoneLabelsAdded');

const createCache = (err, data) => {
    return {
        managedZones: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};

describe('dnsZoneLabelsAdded', function () {
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
        it('should give passing result if the managed zone has labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('labels found for DNS managed zone');
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
                        "labels": {"test": "test"},
                        "visibility": "public",
                        "kind": "dns#managedZone"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
        it('should give failing result if the managed zone does not have labels added', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('does not have any labels');
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
                        "visibility": "public",
                        "kind": "dns#managedZone"
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});