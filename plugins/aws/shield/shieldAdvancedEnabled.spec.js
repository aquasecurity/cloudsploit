var assert = require('assert');
var expect = require('chai').expect;
var shield = require('./shieldAdvancedEnabled');

const createCache = (err, data) => {
    return {
        shield: {
            describeSubscription: {
                'us-east-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('shieldAdvancedEnabled', function () {
    describe('run', function () {
        it('should give error result if shield is not enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Shield subscription is not enabled')
                done()
            };

            const cache = createCache(
                {
                    "message": "The subscription does not exist.",
                    "code": "ResourceNotFoundException",
                    "time": "2019-07-14T03:22:22.346Z",
                    "requestId": "d88682d6-a71c-4529-9f8d-0370e2fe5be5",
                    "statusCode": 400,
                    "retryable": false,
                    "retryDelay": 8.467846411254243
                },
                []
            );

            shield.run(cache, {}, callback);
        })

        it('should give error result if shield end time is not set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Shield subscription is not enabled')
                done()
            };

            const cache = createCache(
                null,
                {
                    StartTime: new Date(),
                    TimeCommitmentInSeconds: 1000,
                    AutoRenew: 'DISABLED',
                    Limits: []
                }
            );

            shield.run(cache, {}, callback);
        })

        it('should give error result if shield subscription has expired', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Shield subscription has expired')
                done()
            };

            const cache = createCache(
                null,
                {
                    StartTime: new Date(),
                    EndTime: new Date('2018-01-01'),
                    TimeCommitmentInSeconds: 1000,
                    AutoRenew: 'DISABLED',
                    Limits: []
                }
            );

            shield.run(cache, {}, callback);
        })

        it('should give error result if shield subscription has auto-renew disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(1)
                expect(results[0].message).to.include('is not configured to auto-renew')
                done()
            };

            const cache = createCache(
                null,
                {
                    StartTime: new Date(),
                    EndTime: new Date('2100-01-01'),
                    TimeCommitmentInSeconds: 1000,
                    AutoRenew: 'DISABLED',
                    Limits: []
                }
            );

            shield.run(cache, {}, callback);
        })

        it('should give passing result if shield subscription is enabled with auto-renew enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is configured to auto-renew')
                done()
            };

            const cache = createCache(
                null,
                {
                    StartTime: new Date(),
                    EndTime: new Date('2100-01-01'),
                    TimeCommitmentInSeconds: 1000,
                    AutoRenew: 'ENABLED',
                    Limits: []
                }
            );

            shield.run(cache, {}, callback);
        })
    })
})