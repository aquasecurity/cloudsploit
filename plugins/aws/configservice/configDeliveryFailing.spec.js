var expect = require('chai').expect;;
var configDeliveryFailing = require('./configDeliveryFailing');

const describeConfigurationRecorderStatus = [
    {
        "name": "default",
        "lastStartTime": "2022-01-18T17:15:22.529000+05:00",
        "recording": true,
        "lastStatus": "SUCCESS",
        "lastStatusChangeTime": "2022-01-19T12:19:56.700000+05:00"
    },
    {
        "name": "default",
        "lastStartTime": "2022-01-18T17:15:22.529000+05:00",
        "recording": true,
        "lastStatus": "FAILURE",
        "lastStatusChangeTime": "2022-01-19T12:19:56.700000+05:00"
    }
];

const createCache = (status) => {
    return {
        configservice: {
            describeConfigurationRecorderStatus: {
                "us-east-1": {
                    data: status               
                },
            }
        }
    }
}

const createNullCache = () => {
    return {
        configservice: {
            describeConfigurationRecorderStatus: {
                "us-east-1": {
                    data: null
                }
            }
        }
    }
}

describe('configDeliveryFailing', () => {
    describe('run', () => {
        it('should PASS if AWS Config service is delivering log files to the designated recipient successfully', () => {
            const cache = createCache([describeConfigurationRecorderStatus[0]]);
            configDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('AWS Config service is delivering log files to the designated recipient successfully');
            })
        });
        it('should FAIL if AWS Config service is not delivering log files to the designated recipient successfully', () => {
            const cache = createCache([describeConfigurationRecorderStatus[1]]);
            configDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('AWS Config service is not delivering log files to the designated recipient successfully');
            })
        });
        it('should PASS if no Config Service configuration recorder statuses found', function (done) {
            const cache = createCache([]);
            configDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Config Service configuration recorder statuses found');
                done();
            });
        });
        it('should UNKNOWN if unable to query for Config Service configuration recorder statuses', () => {
            const cache = createNullCache();
            configDeliveryFailing.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Config Service configuration recorder statuses');
            })
        });
        it('should not return anything if list config services status response is not found', () => {
            configDeliveryFailing.run({}, {}, (err, results) => {
                expect(results.length).to.equal(0);
            })
        });
    });
});