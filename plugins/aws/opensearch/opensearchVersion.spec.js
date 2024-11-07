
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

const createNullCache = () => {
    return {
        opensearch: {
            listDomainNames: {
                'us-east-1': null,
            },
        },
    };
};


 describe('osVersion', function () {
        describe('run', function () {
            it('should give passing result if no opensearch domains present', function (done) {
                const callback = (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(0);
                    expect(results[0].message).to.include('No OpenSearch domains found');
                    expect(results[0].region).to.equal('us-east-1');
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

                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(0);
                    expect(results[0].message).to.include('OpenSearch domain is running the latest version');
                    expect(results[0].region).to.equal('us-east-1');
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
                    expect(results[0].region).to.equal('us-east-1');
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
            it('should UNKNOWN if there was an error listing domain names', function (done) {
                const callback= (err, results) => {
                    expect(results.length).to.equal(1);
                    expect(results[0].status).to.equal(3);
                    expect(results[0].message).to.include('Unable to query for OpenSearch domains');
                    expect(results[0].region).to.equal('us-east-1');
                    done();
                };

                const cache = createErrorCache();
                 es.run(cache,{},callback);
            });
            it('should not return any results if unable to query for domain names', function (done) {
                const callback= (err,results)=>{
                    expect(results.length).to.equal(0);
                    done();
                };
                
                const cache = createNullCache();
                es.run(cache,{},callback);
                    
            });
       });
   });
   
