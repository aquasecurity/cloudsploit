var expect = require('chai').expect;
var plugin = require('./accessApprovalEnabled');

const createCache = (list, err) => {
    return {
        accessApproval: {
            settings: {
                'global': {
                    err: err,
                    data: list
                }
            },
        },
        projects: {
            get: {
                'global': {
                    data: [ { 
                        name: 'testproj'
                    } ]
                }
            }
        }
    }
};

describe('accessApprovalEnabled', function () {
    describe('run', function () {

        it('should give unknown result if unable to query access approval settings', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query access approval settings for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if access approval is enabled for project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('is enabled');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [ {
                    name: 'projects/mytest/accessApprovalSettings',
                    enrolledServices: [ { cloudProduct: 'all', enrollmentLevel: 'BLOCK_ALL' } ]
                  }
                ],
                null
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if access approval is not enabled for project', function (done) {
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

