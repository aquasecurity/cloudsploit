const expect = require('chai').expect;
var esCrossAccountAccess = require('./esCrossAccountAccess');

const domainNames = [
  {
      "DomainName": "test-domain-1"
  },
];

const domains = [
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:11111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::211111111111:user/y"},"Action":"es:*","Resource":"arn:aws:events:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:user/x"},"Action":"es:*","Resource":"arn:aws:events:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
            'AccessPolicies': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"es:*","Resource":"arn:aws:es:us-east-1:111111111111:domain/test-domain-1/*"}]}',
        }
    },
    {
        'DomainStatus': {
            'DomainId': '111111111111/test-domain-1',
            'DomainName': 'test-domain-1',
            'ARN': 'arn:aws:es:us-east-1:111111111111:domain/test-domain-1',
            'Created': true,
            'Deleted': false,
        }
    },
];

const organizationAccounts = [
    {
        "Id": "211111111111",
        "Arn": "arn:aws:organizations::211111111111:account/o-sb9qmv2zif/111111111111",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    },
    {
        "Id": "123456654322",
        "Arn": "arn:aws:organizations::123456654322:account/o-sb9qmv2zif/123456654322",
        "Email": "xyz@gmail.com",
        "Name": "test-role",
        "Status": "ACTIVE",
        "JoinedMethod": "INVITED",
        "JoinedTimestamp": "2020-12-27T10:47:14.057Z"
    }
]

const createCache = (domainNames, domains, accounts, domainNamesErr,domainsErr) => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': {
                    data: domainNames,
                    err: domainNamesErr
                }
            },
            describeElasticsearchDomain: {
                'us-east-1': {
                    'test-domain-1': {
                        data: domains,
                        err: domainsErr
                    }
                }
            }
        },
        sts: {
            getCallerIdentity: {
                'us-east-1':{
                    data: '111111111111'
                }
            }
        },
        organizations: {
            listAccounts: {
                'us-east-1': {
                    data: accounts
                }
            }
        }
    };
};

const createNullCache = () => {
    return {
        es: {
            listDomainNames: {
                'us-east-1': null
            },
            describeElasticsearchDomain: {
                'us-east-1': null
            }
        }
    };
};

describe('esCrossAccountAccess', function () {
    describe('run', function () {

        it('should PASS if ES domain has cross-account access policy attached', function (done) {
            const cache = createCache([domainNames[0]], domains[0]);
            esCrossAccountAccess.run(cache, {"es_whitelisted_aws_account_principals":['arn:aws:iam::211111111111:user/y']}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should PASS if cross-account role contains organization account ID and setting to allow organization account is true', function (done) {
            const cache = createCache([domainNames[0]], domains[0], [organizationAccounts[0]]);
            esCrossAccountAccess.run(cache, { "es_whitelist_aws_organization_accounts": "true" }, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if ES domain does not have cross-account access policy attached', function (done) {
            const cache = createCache([domainNames[0]], domains[1]);
            esCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });
        
        it('should PASS if no ES Domain policy found', function (done) {
            const cache = createCache([domainNames[0]], domains[3]);
            esCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should FAIL if no ES domain found', function (done) {
            const cache = createCache([]);
            esCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });

        it('should UNKNOWN if unable to describe ES domain', function (done) {
            const cache = createCache([], [], [], { message: 'Unable to query ES domains' });
            esCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                done();
            });
        });


        it('should not return anything if query ES domains response not found', function (done) {
            const cache = createNullCache();
            esCrossAccountAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});