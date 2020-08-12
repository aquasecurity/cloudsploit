var assert = require('assert');
var expect = require('chai').expect;
var rds = require('./rdsMinorVersionUpgrade.js');

const createCache = (data) => {
    return {
        rds: {
            describeDBInstances: {
                'us-east-1': {
                    data: data
                }
            }
        }
    }
};

describe('rdsMinorVersionUpgrade', function () {
    describe('run', function () {
        it('should give passing result if AutoMinorVersionUpgrade is enabled', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                expect(results.length).to.equal(1)
                done()
            };

            const cache = createCache(
                [{
                    "AutoMinorVersionUpgrade": true,
                    "DBInstanceIdentifier": "test_id",
                }]
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if AutoMinorVersionUpgrade is not enabled', function(done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                expect(results.length).to.equal(1)
                done()
            };

            const cache = createCache(
                [{
                    "AutoMinorVersionUpgrade": false,
                    "DBInstanceIdentifier": "test_id",
                }]
            );

            rds.run(cache, {}, callback);
        })

        it('should give failing result if AutoMinorVersionUpgrade is not included on the object', function(done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2)
                expect(results.length).to.equal(1)
                done()
            };

            const cache = createCache(
                [{
                    "DBInstanceIdentifier": "test_id",
                }]
            );

            rds.run(cache, {}, callback);
        })

        it('should give passing result if DB descriptors are not passed', function(done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0)
                expect(results.length).to.equal(1)
                done()
            };

            const cache = createCache(
                []
            );

            rds.run(cache, {}, callback);
        })
    })
})