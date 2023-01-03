var expect = require('chai').expect;
var plugin = require('./assetInventoryEnabled');

const createCache = (list, err) => {
    return {
        services: {
            listEnabled: {
                'global': {
                    err: err,
                    data: list
                }
            },
        },
        projects: {
            getWithNumber: {
                'global': {
                    data: [ { 
                        name: 'testproj',
                        projectNumber: 123456
                    } ]
                }
            }
        }
    }
};

describe('assetInventoryEnabled', function () {
    describe('run', function () {

        it('should give unknown result if unable to query services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query services for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if asset inventory is enabled for project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [ {
                    name: 'projects/12345/services/cloudasset.googleapis.com',
                    state: 'ENABLED'
                  }
                ],
                null
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if asset inventory is not enabled for project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('is not enabled');
                expect(results[0].region).to.equal('global')
                done();
            };

            const cache = createCache(
                [],
                null);

            plugin.run(cache, {}, callback);
        });

    })
});

