var assert = require('assert');
var expect = require('chai').expect;
var metrics = require('./monitoringMetrics')

const createCache = (trails, metrics) => {
    return {
        cloudtrail: {
            describeTrails: {
                'us-east-1': {
                    data: trails
                }
            }
        },
        cloudwatchlogs: {
            describeMetricFilters: {
                'us-east-1': {
                    data: metrics
                }
            }
        }
    }
};

describe('monitoringMetrics', function () {
    describe('run', function () {
        it('should give general error if there are not metrics', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(0)
                done()
            };

            metrics.run({}, {}, callback);
        })

        it('should give no results error if there are no metrics', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            };

            const cache = createCache(
                [{
                    HomeRegion: 'us-east-1',
                }],
                []
            );

            metrics.run(cache, {}, callback);
        })

        it('should not give missing metric for a metric that is defined', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].message).to.not.include('Disabled CMKs')
                done()
            };

            const cache = createCache(
                [{
                    HomeRegion: 'us-east-1',
                    CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:the-log-group:*'
                }],
                [{
                    filterName: 'any-filter-name',
                    filterPattern: '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion)) }',
                    logGroupName: 'the-log-group'
                }]
            );

            metrics.run(cache, {}, callback);
        })

        it('should FAIL if trail is not integrated with CloudWatch Logs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('not integrated with CloudWatch Logs');
                done();
            };

            const cache = createCache(
                [{
                    HomeRegion: 'us-east-1',
                    TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail'
                }],
                [{
                    filterName: 'some-filter',
                    filterPattern: '{ ($.eventName = ConsoleLogin) }',
                    logGroupName: 'other-log-group'
                }]
            );

            metrics.run(cache, {}, callback);
        });

        it('should not give missing Unauthorized API Calls for CIS filter pattern', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].message).to.not.include('Unauthorized API Calls');
                done();
            };

            const cache = createCache(
                [{
                    HomeRegion: 'us-east-1',
                    TrailARN: 'arn:aws:cloudtrail:us-east-1:123456789012:trail/test-trail',
                    CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:the-log-group:*'
                }],
                [{
                    filterName: 'unauthorized-api-calls',
                    filterPattern: '{ ($.errorCode ="*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") && ($.sourceIPAddress!="delivery.logs.amazonaws.com") && ($.eventName!="HeadBucket") }',
                    logGroupName: 'the-log-group'
                }]
            );

            metrics.run(cache, {}, callback);
        });

        it('should give missing metric for a metric that is defined with all requirements', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].message).to.include('Disabled CMKs')
                done()
            };

            const cache = createCache(
                [{
                    HomeRegion: 'us-east-1',
                    CloudWatchLogsLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:the-log-group:*'
                }],
                [{
                    filterName: 'any-filter-name',
                    filterPattern: '{($.eventSource = kms.amazonaws.com)}',
                    logGroupName: 'the-log-group'
                }]
            );

            metrics.run(cache, {}, callback);
        })
    })
})