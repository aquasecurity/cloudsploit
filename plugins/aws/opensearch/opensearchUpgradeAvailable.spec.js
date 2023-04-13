var assert = require('assert');
var expect = require('chai').expect;
var es = require('./opensearchUpgradeAvailable');

const createCache = (listData, descData) => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': {
                    err: null,
                    data: listData
                }
            },
            describeDomain: {
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

describe('osUpgradeAvailable', function () {
    describe('run', function () {
        it('should give passing result if no opensearch domains present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No OpenSearch domains found')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            es.run(cache, {}, callback);
        })

        it('should give error result if OpenSearch domain upgrade is available', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('OpenSearch domain service software version: 1 is eligible for an upgrade to version: 2')
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
                    ServiceSoftwareOptions: {
                        CurrentVersion: '1',
                        NewVersion: '2',
                        UpdateAvailable: true,
                        UpdateStatus: 'ELIGIBLE'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if OpenSearch domain is not upgrade eligible', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('OpenSearch domain service software version: 1 is the latest eligible upgraded version')
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
                    ServiceSoftwareOptions: {
                        CurrentVersion: '1',
                        NewVersion: '1',
                        UpdateAvailable: false,
                        UpdateStatus: 'NOT_ELIGIBLE'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })
    })
})