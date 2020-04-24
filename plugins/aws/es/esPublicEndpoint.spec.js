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

describe('esPublicEndpoint', function () {
  describe('run', function () {
    it('should give passing result if no ES domains present with no settings.', function (done) {
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

    it('should give passing result if no ES domains present with setting set to true. ', function (done) {
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give passing result if no ES domains present with setting set to false.', function (done) {
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })

    it('should give error result if ES VPC config is disabled', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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

    it('should give passing result if ES VPC config is disabled with no access policy and setting set to true ', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(0)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint, but is allowed since there are no public access policies.')
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give error result if ES VPC config is disabled without access policy and setting set to false ', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })

    it('should give passing result if ES VPC config is enabled with no settings.', function (done) {
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

    it('should give passing result if ES VPC config is enabled with setting set to true.', function (done) {
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give passing result if ES VPC config is enabled with setting set to false.', function (done) {
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })

    it('should give passing result if Ip condition setting is passed', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(0)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint, but is allowed since there are no public access policies.')
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
            VPCOptions: {},
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give failing result if Ip condition setting is passed, but public policy not allowed', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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
            VPCOptions: {},
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

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })

    it('should give failing result if Ip condition setting is passed, but no setting passed', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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
            VPCOptions: {},
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

      es.run(cache, {}, callback);
    })

    it('should give failing result if no Ip condition setting is passed, but public allowed', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint and has disallowed public access policies.')
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
            VPCOptions: {},
            AccessPolicies: {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal":  "*",
                  "Action": [
                    "es:ESHttp*"
                  ]
                }
              ]
            },
          }
        }
      );

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give failing result if no Ip condition setting is passed, but setting set to false.', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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
            VPCOptions: {},
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
                  ]
                }
              ]
            },
          }
        }
      );

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })

    it('should give failing result if no Ip condition setting is passed, but no setting passed.', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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
            VPCOptions: {},
            AccessPolicies: {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": "*",
                  "Action": [
                    "es:ESHttp*"
                  ]
                }
              ]
            },
          }
        }
      );

      es.run(cache, {}, callback);
    })

    it('should give passing result if no Ip condition setting is passed but a valid principal is, with setting set to true.', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(0)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint, but is allowed since there are no public access policies.')
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
            VPCOptions: {},
            AccessPolicies: {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "AWS": "arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name"
                  },
                  "Action": [
                    "es:ESHttp*"
                  ]
                }
              ]
            },
          }
        }
      );

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: true}, callback);
    })

    it('should give failing result if no Ip condition setting is passed but a valid principal is, with setting set to false.', function (done) {
      const callback = (err, results) => {
        expect(results.length).to.equal(1)
        expect(results[0].status).to.equal(2)
        expect(results[0].message).to.include('ES domain is configured to use a public endpoint.')
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
            VPCOptions: {},
            AccessPolicies: {
              "Version": "2012-10-17",
              "Statement": [
                {
                  "Effect": "Allow",
                  "Principal": {
                    "AWS": "arn:aws:sts::AWS-account-ID:assumed-role/role-name/role-session-name"
                  },
                  "Action": [
                    "es:ESHttp*"
                  ]
                }
              ]
            },
          }
        }
      );

      es.run(cache, {allow_es_public_endpoint_if_ip_condition_policy: false}, callback);
    })
  })
})