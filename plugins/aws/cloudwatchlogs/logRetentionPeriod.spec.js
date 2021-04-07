var assert = require('assert');
var expect = require('chai').expect;
var logs = require('./logRetentionPeriod.js')

const createCache = (groups) => {
    return {
        cloudwatchlogs: {
            describeLogGroups: {
                'us-east-1': {
                    data: groups
                }
            }
        }
    }
};

describe('CloudWatch Log Retention Period', function () {
    describe('run', function () {
        it('should FAIL if the retention is too low', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(2);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 7,
                "arn": "test1",
              }])

            logs.run(cache, { minimum_log_retention_period: 10 }, callback);
        });

        it('should PASS if no CloudWatch Logs log groups found', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([])

            logs.run(cache, { minimum_log_retention_period: 10 }, callback);
        });

        it('should PASS if a Log group retention period is set to never expire', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([{
                "arn": "test1",
              }])

            logs.run(cache, { minimum_log_retention_period: 10 }, callback);
        });

        it('should PASS if retention period greater than the set retention period', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 91,
                "arn": "test1",
              }])

            logs.run(cache, { minimum_log_retention_period: 90 }, callback);
        });

        it('should PASS if retention period equal to the set retention period', function (done) {
            const callback = (err, results) => {
                expect(results[0].status).to.equal(0);
                done()
            };

            const cache = createCache([{
                "retentionInDays": 90,
                "arn": "test1",
              }])

            logs.run(cache, { minimum_log_retention_period: 90 }, callback);
        });
    })
})