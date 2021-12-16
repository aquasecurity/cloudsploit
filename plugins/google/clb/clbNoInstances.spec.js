var expect = require('chai').expect;
var plugin = require('./clbNoInstances');

const createCache = (backendServicesData, backendServicesErr) => {
    return {
        backendServices: {
            list: {
                'global': {
                    err: backendServicesErr,
                    data: backendServicesData
                }
            }
        }
    }
};

describe('clbNoInstances', function () {
    describe('run', function () {
        it('should give unknown result if a unable to query backend services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query backend services');
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
                expect(results[0].message).to.include('No load balancers found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
            );

            plugin.run(cache, {}, callback);
        });


        it('should give passing result if Load Balancers have backend services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('All load balancers have backend services');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                      id: 'projects/my-test-project/global/backendServices',
                      selfLink: 'https://www.googleapis.com/compute/v1/projects/my-test-project/global/backendServices',
                      kind: 'compute#backendServiceList'
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        });
    })
});