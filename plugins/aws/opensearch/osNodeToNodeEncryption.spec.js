var expect = require('chai').expect;
var es = require('./osNodeToNodeEncryption');

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

describe('osNodeToNodeEncryption', function () {
    describe('run', function () {
        it('should give passing result if no OpenSearch domains present', function (done) {
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

        it('should give error result if OpenSearch encryption config is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('OpenSearch domain is not configured to use node-to-node encryption')
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
                    NodeToNodeEncryptionOptions: {
                        Enabled: false
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if OpenSearch encryption config is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('OpenSearch domain is configured to use node-to-node encryption')
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
                    NodeToNodeEncryptionOptions: {
                        Enabled: true
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })
    })
})