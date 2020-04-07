var assert = require('assert');
var expect = require('chai').expect;
var es = require('./esPublicEndpoint');

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

describe.only('esPublicEndpoint', function () {
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

        it('should give error result if ES VPC config is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('ES domain is configured to use a public endpoint')
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
                    VPCOptions: {}
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if ES VPC config is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ES domain is configured to use a VPC endpoint')
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
                    VPCOptions: {
                      VPCId: 'vpc-1234'
                    }
                  }
                }
            );

            es.run(cache, {}, callback);
        })

        it('should give passing result if Ip condition setting is passed', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ES domain is configured to use a public endpoint, but contains an Ip Condition policy')
                done()
            };

            const cache = createCache(
                [
                  {
                    DomainName: 'mydomain'
                  }
                ],
                {
                    AccessPolicies: {
                        "Version": "2012-10-17",
                        "Statement": [
                          {
                            "Effect": "Allow",
                            "Principal": {
                              "AWS": "*"
                            },
                            "Action": [
                                "es:ESHttp*"
                            ],
                            "Condition": {
                              "IpAddress": {
                                "aws:SourceIp": [
                                  "192.0.2.0/24"
                                ]
                              }
                            },
                          }
                        ]
                    },
                    DomainStatus: {
                        DomainName: 'mydomain',
                        ARN: 'arn:1234',
                        VPCOptions: {}
                    }
                }
            );

            es.run(cache, {allow_public_only_if_ip_condition_policy: true}, callback);
        })
    })
})