var expect = require('chai').expect;
var plugin = require('./okePrivateEndpoint');

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
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('okePrivateEndpoint', function () {
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

        it('should give failing result if OKE cluster does not have private endpoint enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('does not have private endpoint enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
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
                    }
                ]

            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if oke cluster has private endpoint enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('has private endpoint enabled')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        "id": "cluster1",
                        "name": "cluster1",
                        "endpoints": {
                            "kubernetes": null,
                            "publicEndpoint": null,
                            "privateEndpoint": "10.0.0.0:8080",
                        },
                        "endpointConfig": {
                            "isPublicIpEnabled": false
                        },
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        });
    });
});