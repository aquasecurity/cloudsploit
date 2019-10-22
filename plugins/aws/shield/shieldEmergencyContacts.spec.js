var assert = require('assert');
var expect = require('chai').expect;
var shield = require('./shieldEmergencyContacts');

const createCache = (err, data) => {
    return {
        shield: {
            describeEmergencyContactSettings: {
                'us-east-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('shieldEmergencyContacts', function () {
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

        it('should give error result if shield emergency contacts are not set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Shield emergency contacts are not configured')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            shield.run(cache, {}, callback);
        })

        it('should give passing result if shield emergency contacts are set', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Shield emergency contacts are configured with')
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        EmailAddress: 'test@example.com'
                    }
                ]
            );

            shield.run(cache, {}, callback);
        })
    })
})