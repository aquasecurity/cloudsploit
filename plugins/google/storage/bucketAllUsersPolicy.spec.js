var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./bucketAllUsersPolicy');

const createCache = (err, data) => {
    return {
        buckets: {
            getIamPolicy: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('bucketAllUsersPolicy', function () {
    describe('run', function () {
        it('should give unknown result if a bucket error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query storage buckets');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                ['error'],
                null,
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no buckets are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No storage buckets found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [],
            );

            plugin.run(cache, {}, callback);
        });
        it('should give passing result if no bucks have anonymous or public access', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No buckets have anonymous or public access.');
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
                expect(results[0].message).to.include('The following buckets have anonymous or public access');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/us.artifacts.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/staging.rosy-booth-253119.appspot.com",
                        "bindings": [
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAE=",
                        "version": 1
                    },
                    {
                        "kind": "storage#policy",
                        "resourceId": "projects/_/buckets/rosy-booth-253119.appspot.com",
                        "version": 1,
                        "bindings": [
                            {
                                "role": "roles/iam.securityReviewer",
                                "members": [
                                    "allUsers"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketOwner",
                                "members": [
                                    "projectEditor:rosy-booth-253119",
                                    "projectOwner:rosy-booth-253119"
                                ]
                            },
                            {
                                "role": "roles/storage.legacyBucketReader",
                                "members": [
                                    "allUsers",
                                    "projectViewer:rosy-booth-253119"
                                ]
                            }
                        ],
                        "etag": "CAs="
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })
    })
});