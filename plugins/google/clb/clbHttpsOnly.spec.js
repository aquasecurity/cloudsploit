var expect = require('chai').expect;
var plugin = require('./clbHttpsOnly');

const createCache = (urlMapsData, urlMapsErr, targetHttpProxiesData, targetHttpProxiesErr) => {
    return {
        urlMaps: {
            list: {
                'global': {
                    err: urlMapsErr,
                    data: urlMapsData
                }
            }
        },
        targetHttpProxies: {
            list: {
                'global': {
                    err: targetHttpProxiesErr,
                    data: targetHttpProxiesData
                }
            }
        }
    }
};

describe('clbHttpsOnly', function () {
    describe('run', function () {
        it('should give unknown result if a unable to query Load Balancers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Load Balancer');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                ['error'],
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no Load Balancers are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Load Balancers found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if Load Balancer is HTTPS-Only', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Load Balancer is HTTPS-Only');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "3272419801760278187",
                        "creationTimestamp": "2021-09-24T02:20:04.204-07:00",
                        "name": "test-clb",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/urlMaps/test-clb",
                        "defaultService": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/backendServices/test-bes",
                        "fingerprint": "dt7lg_mdH8s=",
                        "kind": "compute#urlMap"
                    }
                ],
                null,
                [],
                null,
            );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if Load Balancer is not HTTPS-Only', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Load Balancer is not HTTPS-Only');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        "id": "3272419801760278187",
                        "creationTimestamp": "2021-09-24T02:20:04.204-07:00",
                        "name": "test-clb",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/urlMaps/test-clb",
                        "defaultService": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/backendServices/test-bes",
                        "fingerprint": "dt7lg_mdH8s=",
                        "kind": "compute#urlMap"
                    }
                ],
                null,
                [
                    {
                        "id": "8080803103162504571",
                        "creationTimestamp": "2021-09-24T03:42:28.691-07:00",
                        "name": "lb-target-2",
                        "selfLink": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/targetHttpProxies/lb-target-2",
                        "urlMap": "https://www.googleapis.com/compute/v1/projects/aqua-test/global/urlMaps/test-clb",
                        "fingerprint": "Mk7MijcwFNc=",
                        "kind": "compute#targetHttpProxy"
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })
    })
});