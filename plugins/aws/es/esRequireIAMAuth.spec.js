var assert = require('assert');
var expect = require('chai').expect;
var es = require('./esRequireIAMAuth');

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

describe('esPublicEndpoint', function() {
    describe('run', function() {
        it('should give passing result if no ES domains present', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No ElasticSearch domains found')
                done()
            };

            const cache = createCache(
                [],
                {}
            );

            es.run(cache, { es_require_iam_authentication: true }, callback);
        })

        it('should give positive result if there are no access policies', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ElasticSearch domain has no access policies')
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
                    }
                }
            );

            es.run(cache, { es_require_iam_authentication: true }, callback);
        })

        it('should give error result if Principal is global', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('ElasticSearch domain has policy that does not require IAM authentication')
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

                    }
                }
            );

            es.run(cache, { es_require_iam_authentication: true }, callback);
        })

        it('should give error result if Principal does not exist', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('ElasticSearch domain has policy that does not require IAM authentication')
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
                        AccessPolicies: {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
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

                    }
                }
            );

            es.run(cache, { es_require_iam_authentication: true }, callback);
        })

        it('should give error result if Principal does not exist', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('ElasticSearch domain access policies require IAM authentication')
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
                        AccessPolicies: {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Deny",
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

                    }
                }
            );

            es.run(cache, { es_require_iam_authentication: true }, callback);
        })

    })

})
