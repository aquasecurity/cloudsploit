var assert = require('assert');
var expect = require('chai').expect;
var es = require('./esLoggingEnabled');

const createCache = (listData, descData) => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    'mydomain': {
                        err: null,
                        data: descData
                    }
                }
            }
        }
    }
};

describe('esLoggingEnabled', function () {
    describe('run', function () {
        it('should give passing result if no ES domains present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No ES domains found')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            es.run(cache, {}, callback);
        })

        it('should give error result if ES logging is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('ES domain logging is not enabled')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                  DomainStatus: {
                    DomainName: 'mydomain',
                    ARN: 'arn:1234',
                    LogPublishingOptions: {
                        Enabled: false
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give failing result if ES logging is enabled without CloudWatch', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('ES domain logging is enabled but logs are not configured to be sent to CloudWatch')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                  DomainStatus: {
                    DomainName: 'mydomain',
                    ARN: 'arn:1234',
                    LogPublishingOptions: {
                        Enabled: true
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if ES logging is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ES domain logging is enabled and sending logs to CloudWatch')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                  DomainStatus: {
                    DomainName: 'mydomain',
                    ARN: 'arn:1234',
                    LogPublishingOptions: {
                        Enabled: true,
                        CloudWatchLogsLogGroupArn: 'arn:1234'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })
    })
})