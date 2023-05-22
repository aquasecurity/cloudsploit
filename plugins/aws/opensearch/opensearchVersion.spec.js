
var expect = require('chai').expect;
var es = require('./opensearchVersion');

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
const createErrorCache = () => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': {
                    err: {
                        message: 'error listing domain names'
                    },
                },
            },
        },
    };
};

 describe('osVersion', function () {
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
            it('should give passing result the version of opensearch is engine version is 7.10', function (done) {
                const callback = (err, results) => {

                    expect(results.length).to.equal(1)
                    expect(results[0].status).to.equal(0)
                    expect(results[0].message).to.include('OpenSearch domain is running the latest version')
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
                            EngineVersion: 'Elasticsearch_7.10.'
                            }}
                );

                es.run(cache, {}, callback);
            })

            it('should give error result if OpenSearch domain is not running the latest version', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('OpenSearch domain should be upgraded to latest version');
                    done();
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
                            EngineVersion: 'OpenSearch_1.5'
                        }
                    }
                );

                es.run(cache, {}, callback);
            })
            it('should give error result if OpenSearch domain engine version is undefined', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(2);
                    expect(results[0].message).to.include('Unknown engine version');
                    done();
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
                        }
                    }
                );

                es.run(cache, {}, callback);
            })
            it('should UNKNOWN if there was an error listing domain names', function (done) {
                const callback= (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(3);
                    done();
                };

                const cache = createErrorCache();
                 es.run(cache,{},callback);
            });
        })
    })
