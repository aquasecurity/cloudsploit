var expect = require('chai').expect;
var plugin = require('./okeSecretsEncrypted');

const getCluster = [
    {
        "id": "cluster1",
        "name": "cluster1",
        "endpointConfig": {
            "isPublicIpEnabled": true
        },
        "endpoints": {
            "kubernetes": null,
            "publicEndpoint": "10.0.0.0:8080",
            "privateEndpoint": null,
        },
    },
    {
        "id": "cluster1",
        "name": "cluster1",
        "endpointConfig": {
            "isPublicIpEnabled": true
        },
        "endpoints": {
            "kubernetes": null,
            "publicEndpoint": "10.0.0.0:8080",
            "privateEndpoint": null,
        },
        "kmsKeyId": 'key-1'
    }
];

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        cluster: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        vault: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "displayName": "vault-1",
                            "freeformTags": {},
                            "id": "vault-1",
                            "lifecycleState": "ACTIVE",
                        },
                    ]
                }
            }
        },
        keys: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "definedTags": {},
                            "displayName": "key-1",
                            "freeformTags": {},
                            "id": "key-1",
                            "lifecycleState": "ENABLED",
                            "timeCreated": "2022-04-30T19:49:12.841Z",
                            "vaultId": "vault-1",
                            "protectionMode": "SOFTWARE",
                            "algorithm": "AES"
                        }
                    ],
                
                }
            }
        }
    }
};

describe('okeSecretsEncrypted', function () {
    describe('run', function () {
        it('should give unknown result if a cluster error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for OKE clusters')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no oke clusters are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No OKE clusters found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })


        it('should give failing result if oke cluster does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('which is less')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [getCluster[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if oke cluster has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('which is greater than or equal to')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [getCluster[1]]
            );

            plugin.run(cache, {}, callback);
        });
    });
});